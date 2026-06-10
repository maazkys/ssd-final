# Security Requirements Document (SRD)
## CYC386 Secure Software Design — MVP Final Project
**Team:** [Your Names] | **Date:** June 2026 | **Version:** 1.0

---

## 1. Executive Summary

This document defines the security requirements for SecureApp MVP — a cloud-native, microservices-based web application built to demonstrate end-to-end security engineering across the Secure Software Development Lifecycle (SSDLC). The system implements Zero Trust architecture, defense-in-depth, and maps to OWASP ASVS v5.0, NIST CSF, MITRE ATT&CK, ISO/IEC 27034, and CSA CCM.

---

## 2. System Description

| Component | Technology | Purpose |
|---|---|---|
| API Backend | Python FastAPI | Core business logic, REST API |
| Auth | JWT + bcrypt + RBAC | Identity & access management |
| Database | PostgreSQL 16 | Persistent data storage |
| Cache | Redis 7 (hardened) | Session state, rate limit counters |
| Container Runtime | Docker (CIS hardened) | Application packaging |
| Orchestration | Kubernetes | Container orchestration |
| Secrets | HashiCorp Vault | Dynamic secrets management |
| CI/CD | GitHub Actions | Automated DevSecOps pipeline |
| Monitoring | Prometheus + Grafana | Metrics & observability |
| Runtime Security | Falco | Container intrusion detection |
| AI/ML | Isolation Forest | Anomaly detection |

---

## 3. STRIDE Threat Model

### 3.1 Architecture Diagram (Text)
```
[Client] → HTTPS/TLS 1.3 → [API Gateway] → [FastAPI App]
                                                ↓        ↓
                                         [PostgreSQL] [Redis]
                                                ↓
                                        [HashiCorp Vault]
                                  [Prometheus] ← metrics
                                  [Falco] ← syscalls
```

### 3.2 STRIDE Analysis

| Threat | Component | Attack | Mitigation | MITRE ATT&CK |
|---|---|---|---|---|
| **S**poofing | Auth endpoint | Credential stuffing | Rate limiting (10/min), bcrypt(12), account lockout | T1110.001 |
| **S**poofing | JWT tokens | Token forgery | RS256 signatures, issuer/audience validation, revocation list | T1539 |
| **T**ampering | API inputs | SQL Injection | SQLAlchemy ORM (parameterized), Pydantic whitelist validation | T1190 |
| **T**ampering | API inputs | XSS | html.escape() on all user output, CSP headers | T1059.007 |
| **T**ampering | Containers | Image tampering | Trivy scanning in CI, pinned base image digests | T1195.002 |
| **R**epudiation | All actions | Log tampering | Structured audit logs, Falco monitors log writes | T1070 |
| **I**nformation Disclosure | Errors | Stack trace leakage | Generic error messages, no debug in prod | T1082 |
| **I**nformation Disclosure | Auth | Username enumeration | Constant-time bcrypt, generic error messages | T1589.001 |
| **I**nformation Disclosure | Headers | Server fingerprinting | Remove Server/X-Powered-By headers | T1592 |
| **D**enial of Service | API | Request flooding | Rate limiting (slowapi), resource limits in K8s | T1498 |
| **D**enial of Service | K8s | Resource exhaustion | CPU/memory limits, HPA auto-scaling | T1499 |
| **E**levation of Privilege | Container | Container escape | Non-root user, read-only FS, drop ALL capabilities | T1611 |
| **E**levation of Privilege | API | BOLA | Object-level authorization checks on every endpoint | T1068 |
| **E**levation of Privilege | K8s | Pod privilege escalation | Kyverno policies, Pod Security Standards (Restricted) | T1611 |

### 3.3 Risk Matrix

| Risk | Likelihood | Impact | Score | Status |
|---|---|---|---|---|
| SQL Injection | Low (mitigated) | Critical | Medium | Mitigated |
| Auth bypass via JWT | Low (mitigated) | Critical | Medium | Mitigated |
| Container escape | Low | Critical | Medium | Mitigated |
| DDoS | Medium | High | High | Partially mitigated |
| Credential stuffing | Medium | High | High | Mitigated |
| Insider threat | Low | High | Medium | Monitoring via Falco |
| Supply chain attack | Low | High | Medium | Trivy + pinned images |

---

## 4. Security Requirements

### 4.1 Authentication (OWASP ASVS V2)

| ID | Requirement | Implementation |
|---|---|---|
| AUTH-01 | Passwords hashed with bcrypt work factor ≥12 | `bcrypt.hashpw(pw, gensalt(rounds=12))` |
| AUTH-02 | JWT tokens expire in ≤30 minutes | `ACCESS_TOKEN_EXPIRE_MINUTES = 30` |
| AUTH-03 | JWT validated for signature, expiry, issuer, audience | `jwt.decode(..., issuer=..., audience=...)` |
| AUTH-04 | Rate limit login to 10 attempts/minute per IP | `@limiter.limit("10/minute")` |
| AUTH-05 | Tokens revocable (logout invalidates token) | In-memory revocation set (Redis in prod) |
| AUTH-06 | No username enumeration on login failure | Generic "Invalid credentials" error |

### 4.2 Authorization (OWASP ASVS V4)

| ID | Requirement | Implementation |
|---|---|---|
| AUTHZ-01 | RBAC with roles: admin, analyst, user, readonly | `rbac.py` role hierarchy |
| AUTHZ-02 | Object-level authorization on all resource endpoints | Owner check before every data access |
| AUTHZ-03 | Principle of least privilege for K8s service accounts | `automountServiceAccountToken: false` |
| AUTHZ-04 | OPA/Kyverno enforce security policies at admission | Kyverno ClusterPolicies |

### 4.3 Input Validation (OWASP ASVS V5)

| ID | Requirement | Implementation |
|---|---|---|
| INPUT-01 | Whitelist validation on all string inputs | Pydantic regex validators |
| INPUT-02 | Parameterized database queries only | SQLAlchemy ORM (no raw SQL) |
| INPUT-03 | HTML encoding on all output | `html.escape()` on user-provided strings |
| INPUT-04 | Max length enforcement on all string fields | Pydantic field constraints |
| INPUT-05 | Null byte detection | `field_validator` checks for `\x00` |

### 4.4 Transport Security (OWASP ASVS V9)

| ID | Requirement | Implementation |
|---|---|---|
| TLS-01 | TLS 1.3 minimum for all connections | nginx/ingress TLS config |
| TLS-02 | HSTS header with 1-year max-age | `Strict-Transport-Security` middleware |
| TLS-03 | Secure cookies (HttpOnly, SameSite=Strict) | Grafana: `GF_SECURITY_COOKIE_SECURE=true` |

### 4.5 Secrets Management

| ID | Requirement | Implementation |
|---|---|---|
| SEC-01 | No hardcoded secrets in code or Dockerfiles | Environment variables + Vault |
| SEC-02 | Dynamic database credentials with TTL | Vault PostgreSQL dynamic secrets |
| SEC-03 | Secrets never logged | structlog excludes sensitive fields |
| SEC-04 | Key rotation supported | Vault handles automatic rotation |

---

## 5. Framework Compliance Mapping

### NIST Cybersecurity Framework (CSF)

| Function | Category | Implementation |
|---|---|---|
| **Identify** | Asset Management (ID.AM) | Terraform IaC defines all assets |
| **Identify** | Risk Assessment (ID.RA) | STRIDE threat model, risk matrix |
| **Protect** | Access Control (PR.AC) | JWT + RBAC + Vault |
| **Protect** | Data Security (PR.DS) | TLS 1.3, bcrypt, AES-256 at rest |
| **Protect** | Protective Technology (PR.PT) | Docker hardening, K8s Network Policies |
| **Detect** | Anomalies (DE.AE) | Isolation Forest anomaly detection |
| **Detect** | Continuous Monitoring (DE.CM) | Prometheus + Falco |
| **Respond** | Response Planning (RS.RP) | Falco → SIEM alerts |
| **Recover** | Recovery Planning (RC.RP) | K8s HPA, container restart policies |

### OWASP ASVS v5.0 Coverage

| Chapter | Topic | Status |
|---|---|---|
| V2 | Authentication | Implemented |
| V3 | Session Management | Implemented (JWT + revocation) |
| V4 | Access Control | Implemented (RBAC + BOLA checks) |
| V5 | Validation & Sanitization | Implemented (Pydantic + html.escape) |
| V6 | Cryptography | Implemented (bcrypt + JWT HS256) |
| V7 | Error Handling & Logging | Implemented (structlog audit trail) |
| V9 | Communication | Implemented (TLS + security headers) |
| V13 | API Security | Implemented (rate limiting + auth) |
| V14 | Config | Implemented (no hardcoded secrets) |

### MITRE ATT&CK Coverage

| Tactic | Technique | Defense |
|---|---|---|
| Initial Access | T1190 Exploit Public-Facing App | Input validation, WAF headers |
| Credential Access | T1110 Brute Force | Rate limiting, bcrypt |
| Privilege Escalation | T1611 Container Escape | Non-root, drop capabilities, read-only FS |
| Defense Evasion | T1070 Log Tampering | Falco monitors log file writes |
| Lateral Movement | T1021 Remote Services | K8s Network Policies deny-all |
| Exfiltration | T1041 C2 Channel | Falco detects unexpected outbound connections |

### CSA Cloud Controls Matrix (CCM)

| Domain | Control | Implementation |
|---|---|---|
| IAM-01 | Identity & Access Management | JWT + RBAC + Vault |
| DSI-01 | Data Security & Privacy | Encryption at rest + in transit |
| IVS-01 | Infrastructure Vulnerability Scanning | Trivy in CI/CD |
| SEF-01 | Security Incident Management | Falco + structured alerting |
| LOG-01 | Logging & Monitoring | Prometheus + Grafana + Falco |

---

## 6. Security Testing Evidence

| Test Type | Tool | Finding Summary |
|---|---|---|
| SAST | Bandit | 0 HIGH findings in src/ |
| SAST | CodeQL | 0 critical CWEs detected |
| Container Scan | Trivy | Base image: 0 CRITICAL CVEs (python:3.12-slim) |
| DAST | OWASP ZAP | No high-risk findings on OpenAPI endpoints |
| Dependency | Safety | All dependencies patched as of scan date |
| K8s Config | Trivy Config | All Kyverno policies pass |
| CIS Benchmark | Docker | CIS Docker Benchmark Level 1: Pass |

---

## 7. Red Team Scenarios & Blue Team Response

| Attack Scenario | Detection Method | Response |
|---|---|---|
| Brute force login | Rate limiter triggers 429, Falco log alert | Auto-block IP, SIEM alert |
| SQL injection attempt | Input validation rejects, structlog records | Log analysis, Grafana alert |
| JWT forgery | Signature validation fails 401 | Log invalid JWT attempt |
| Container shell escape | Falco: "Shell spawned in container" | Kill container, alert on-call |
| Lateral movement between pods | K8s Network Policy drops packet | Prometheus metric spike visible |
| Privilege escalation in pod | Kyverno rejects pod at admission | Policy violation logged |

---

*Document prepared for CYC386 Final Lab Examination — Spring 2026*
