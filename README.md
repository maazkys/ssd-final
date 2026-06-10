# SecureApp MVP — CYC386 Final Lab Project
> End-to-End Secure Cloud-Native DevSecOps Platform

## Team Roles
| Member | Role |
|---|---|
| [Name 1] | Lead Developer (Secure Coding, Docker) |
| [Name 2] | Security Analyst (Threat Model, DAST, AI/ML) |
| [Name 3] | DevSecOps Engineer (K8s, IaC, Monitoring) |
| [Name 4] | Red/Blue Team Professional |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Zero Trust Boundary                   │
│  ┌──────────┐    TLS 1.3    ┌────────────────────────┐  │
│  │  Client  │──────────────▶│   FastAPI Application  │  │
│  └──────────┘               │   JWT + RBAC + Audit   │  │
│                             └──────────┬───────────┬─┘  │
│                                        │           │     │
│                             ┌──────────▼──┐  ┌─────▼──┐ │
│                             │ PostgreSQL  │  │ Redis  │ │
│                             │  (ORM only) │  │ (TLS)  │ │
│                             └─────────────┘  └────────┘ │
│  ┌───────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │ Prometheus│  │  Falco   │  │   HashiCorp Vault     │  │
│  │ + Grafana │  │(Runtime) │  │  (Dynamic Secrets)   │  │
│  └───────────┘  └──────────┘  └──────────────────────┘  │
│  ┌─────────────────────────────────────────────────────┐ │
│  │        GitHub Actions CI/CD (SAST→Scan→DAST→Push)   │ │
│  └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start (2 commands)

### Prerequisites
- Docker + Docker Compose
- Python 3.12+

### 1. Set environment variables
```bash
cp .env.example .env
# Edit .env with your secrets (see below)
```

**.env.example:**
```
JWT_SECRET_KEY=change-me-to-32-plus-random-chars
DB_PASSWORD=StrongPass123!
REDIS_PASSWORD=StrongPass123!
GRAFANA_PASSWORD=admin123
```

### 2. Start the full stack
```bash
cd docker
docker compose up -d
```

### Services
| Service | URL | Credentials |
|---|---|---|
| API | http://localhost:8000 | JWT-based |
| API Docs | http://localhost:8000/api/docs | — |
| Prometheus | http://localhost:9090 | — |
| Grafana | http://localhost:3000 | admin / $GRAFANA_PASSWORD |

---

## Project Structure
```
devsecops-mvp/
├── src/                    # Application source
│   ├── main.py             # FastAPI app, middleware
│   ├── auth/
│   │   ├── jwt_handler.py  # JWT creation & validation
│   │   └── rbac.py         # Role-Based Access Control
│   ├── api/
│   │   ├── users.py        # Auth endpoints
│   │   └── items.py        # CRUD with BOLA protection
│   ├── models/             # SQLAlchemy ORM models
│   └── anomaly_detector.py # AI/ML Isolation Forest
├── docker/
│   ├── Dockerfile          # CIS-hardened multi-stage build
│   └── docker-compose.yml  # Full stack
├── k8s/
│   ├── base/deployment.yaml    # K8s manifests (Pod Security)
│   └── policies/kyverno-*.yaml # Policy-as-Code
├── iac/
│   └── main.tf             # Terraform + Vault
├── .github/workflows/
│   └── devsecops.yml       # CI/CD: SAST→Trivy→ZAP→Push
├── monitor/
│   ├── prometheus/         # Prometheus config
│   └── falco/              # Custom Falco rules
└── docs/
    └── SRD_and_Threat_Model.md  # Full security documentation
```

---

## Security Features Demonstrated

### 1. Secure Coding (20% weight)
- Pydantic whitelist input validation (no raw string queries)
- SQLAlchemy ORM — parameterized queries, zero raw SQL
- bcrypt(12) password hashing with constant-time comparison
- JWT with issuer/audience validation + revocation
- HTML escaping on all user output (XSS prevention)
- Security headers middleware (CSP, HSTS, X-Frame-Options, etc.)
- No secrets in code — all via environment/Vault

### 2. Docker Security (15% weight)
- Multi-stage build (no build tools in production image)
- Non-root user (UID 1001)
- Read-only root filesystem
- ALL capabilities dropped, only NET_BIND_SERVICE added
- `no-new-privileges` security option
- CIS Docker Benchmark Level 1 compliant

### 3. Kubernetes Security (15% weight)
- Pod Security Standards: `restricted` profile enforced
- Network Policies: default deny-all, explicit allow rules
- RBAC: dedicated ServiceAccount, minimal permissions
- Kyverno policies: non-root, read-only FS, no latest tag, resource limits
- `automountServiceAccountToken: false`
- seccompProfile: RuntimeDefault

### 4. CI/CD Pipeline (10% weight)
- Bandit SAST → CodeQL → Safety dependency scan
- Trivy container vulnerability scan (fails on CRITICAL)
- Trivy IaC/config scan
- OWASP ZAP DAST against live app
- Only pushes to registry if ALL security gates pass

### 5. Monitoring & Runtime Security (10% weight)
- Prometheus metrics exported from FastAPI
- Falco custom rules: shell spawn, unexpected outbound, privilege escalation
- Structured audit logs on every request/response
- AI/ML Isolation Forest anomaly detection on Prometheus metrics

### 6. IaC & Secrets (10% weight)
- Terraform provisions Vault KV engine, AppRole auth, dynamic DB credentials
- All secrets loaded at runtime from Vault
- Secrets have TTL + automatic rotation

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | /api/v1/users/register | None | Register user |
| POST | /api/v1/users/login | None | Get JWT |
| POST | /api/v1/users/logout | Bearer | Revoke token |
| GET | /api/v1/users/me | Bearer | Current user |
| GET | /api/v1/users/all | Admin | List all users |
| POST | /api/v1/items/ | Bearer | Create item |
| GET | /api/v1/items/{id} | Bearer (owner) | Get item |
| DELETE | /api/v1/items/{id} | Bearer (owner) | Delete item |
| GET | /api/v1/secure-data | Bearer | Rate-limited secure data |
| GET | /health | None | Health check |
| GET | /metrics | None | Prometheus metrics |

---

## Demo Script (Red/Blue Team Scenarios)

### Blue Team: Show normal operation
```bash
# Register + login
curl -X POST http://localhost:8000/api/v1/users/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@test.com","password":"SecurePass123!"}'

TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/users/login \
  -d '{"username":"alice","password":"SecurePass123!"}' | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/users/me
```

### Red Team: Demonstrate attacks are blocked
```bash
# SQL injection attempt (blocked by Pydantic + ORM)
curl -X POST http://localhost:8000/api/v1/users/login \
  -d '{"username":"admin'\'' OR 1=1--","password":"x"}'
# → 422 Unprocessable Entity (validation rejects non-alphanumeric)

# Brute force (blocked by rate limiter after 10 requests)
for i in {1..15}; do
  curl -X POST http://localhost:8000/api/v1/users/login \
    -d '{"username":"admin","password":"wrong'$i'"}'
done
# → 429 Too Many Requests after 10 attempts

# BOLA: access another user's item (blocked)
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/items/OTHER_USER_ITEM_ID
# → 404 (not 403 — no resource existence disclosure)
```

---

## Framework Compliance Summary

| Framework | Coverage |
|---|---|
| OWASP ASVS v5.0 | V2,V3,V4,V5,V6,V7,V9,V13,V14 |
| NIST CSF | All 5 functions |
| MITRE ATT&CK | 6 tactics mapped with mitigations |
| CIS Docker Benchmark | Level 1 |
| CIS Kubernetes Benchmark | Chapter 5 |
| CSA CCM | IAM, DSI, IVS, SEF, LOG domains |
| ISO/IEC 27034 | Application security controls |

---

*CYC386 Secure Software Design & Development — Spring 2026*
*Instructor: Engr. Muhammad Ahmad Nawaz, COMSATS University Islamabad*
