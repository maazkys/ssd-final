# ─────────────────────────────────────────────────────────────────────────────
# Terraform IaC — CYC386 MVP
# Provisions: HashiCorp Vault secrets, Kubernetes namespace config
# Maps to: NIST CSF PR.AC-1 (Identity Management)
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.29"
    }
  }

  # Remote state (use for team — never commit local state)
  backend "local" {
    path = "terraform.tfstate"
  }
}

# ── Variables ─────────────────────────────────────────────────────────────────
variable "vault_addr" {
  description = "HashiCorp Vault address"
  type        = string
  default     = "http://localhost:8200"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "development"
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be development, staging, or production."
  }
}

# ── Providers ─────────────────────────────────────────────────────────────────
provider "vault" {
  address = var.vault_addr
  # Token sourced from VAULT_TOKEN env variable — never hardcode
}

# ── Vault: Enable KV Secrets Engine ──────────────────────────────────────────
resource "vault_mount" "kv" {
  path        = "secureapp"
  type        = "kv-v2"
  description = "KV v2 secrets engine for SecureApp MVP"
}

# Store application secrets in Vault
resource "vault_kv_secret_v2" "app_secrets" {
  mount               = vault_mount.kv.path
  name                = "${var.environment}/app"
  delete_all_versions = false

  data_json = jsonencode({
    # In real usage: generate these with random_password resource
    JWT_SECRET_KEY = "REPLACE_WITH_GENERATED_SECRET"
    DB_PASSWORD    = "REPLACE_WITH_GENERATED_SECRET"
    REDIS_PASSWORD = "REPLACE_WITH_GENERATED_SECRET"
  })

  lifecycle {
    # Prevent accidental secret destruction
    prevent_destroy = true
    # Ignore changes (secrets managed externally after init)
    ignore_changes = [data_json]
  }
}

# ── Vault: AppRole Auth for Application ──────────────────────────────────────
resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_approle_auth_backend_role" "secureapp" {
  backend        = vault_auth_backend.approle.path
  role_name      = "secureapp-role"
  token_policies = ["secureapp-policy"]
  token_ttl      = 3600   # 1 hour token TTL
  token_max_ttl  = 86400  # 24 hour max
}

# ── Vault: Policy for SecureApp (least privilege) ─────────────────────────────
resource "vault_policy" "secureapp" {
  name = "secureapp-policy"

  policy = <<EOT
# Allow reading app secrets only
path "secureapp/data/${var.environment}/app" {
  capabilities = ["read"]
}

# Allow token renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}
EOT
}

# ── Vault: Dynamic database credentials (PostgreSQL) ─────────────────────────
resource "vault_mount" "db" {
  path = "database"
  type = "database"
}

resource "vault_database_secret_backend_connection" "postgres" {
  backend       = vault_mount.db.path
  name          = "secureapp-postgres"
  allowed_roles = ["secureapp-db-role"]

  postgresql {
    connection_url = "postgresql://{{username}}:{{password}}@postgres:5432/secureapp"
    username       = "vault_admin"
    password       = "REPLACE_WITH_VAULT_ADMIN_PASSWORD"
  }
}

resource "vault_database_secret_backend_role" "secureapp" {
  backend             = vault_mount.db.path
  name                = "secureapp-db-role"
  db_name             = vault_database_secret_backend_connection.postgres.name
  default_ttl         = "1h"
  max_ttl             = "24h"
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
  ]
  revocation_statements = [
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]
}

# ── Outputs ───────────────────────────────────────────────────────────────────
output "vault_kv_path" {
  value       = vault_mount.kv.path
  description = "Vault KV mount path"
}

output "approle_role_id" {
  value       = vault_approle_auth_backend_role.secureapp.role_id
  description = "AppRole Role ID for SecureApp"
  sensitive   = false
}
