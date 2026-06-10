"""
CYC386 Secure Software Design - MVP Application
Demonstrates: JWT Auth, RBAC, Input Validation, Rate Limiting, Secure Headers
"""

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from prometheus_fastapi_instrumentator import Instrumentator
import structlog
import time

from auth.jwt_handler import verify_token, create_access_token
from auth.rbac import require_role, Roles
from api.users import router as users_router
from api.items import router as items_router
from models.database import init_db

# Structured logging
logger = structlog.get_logger()

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="SecureApp MVP",
    description="CYC386 - Secure Cloud-Native Application",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url=None,  # Disable in prod
    openapi_url="/api/openapi.json",
)

# ── Security Middleware ──────────────────────────────────────────────────────

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # No wildcard in prod
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "*", "127.0.0.1"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add OWASP recommended security headers"""
    start_time = time.time()
    response = await call_next(request)

    # Security headers (OWASP ASVS v5 requirement)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; img-src 'self' data: fastapi.tiangolo.com"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Process-Time"] = str(time.time() - start_time)

    # Remove info-leaking headers
    if "server" in response.headers:
        del response.headers["server"]
    if "x-powered-by" in response.headers:
        del response.headers["x-powered-by"]

    return response


@app.middleware("http")
async def audit_log(request: Request, call_next):
    """Audit logging for all requests - NIST CSF DE.CM requirement"""
    request_id = request.headers.get("X-Request-ID", "none")
    logger.info(
        "request_received",
        method=request.method,
        path=request.url.path,
        client_ip=get_remote_address(request),
        request_id=request_id,
    )
    response = await call_next(request)
    logger.info(
        "request_completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        request_id=request_id,
    )
    return response


# ── Prometheus Metrics ───────────────────────────────────────────────────────
Instrumentator().instrument(app).expose(app)

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(users_router, prefix="/api/v1/users", tags=["users"])
app.include_router(items_router, prefix="/api/v1/items", tags=["items"])


@app.on_event("startup")
async def startup_event():
    await init_db()
    logger.info("application_started", version="1.0.0")


@app.get("/health", include_in_schema=False)
async def health_check():
    return {"status": "healthy", "service": "secureapp-mvp"}


@app.get("/api/v1/secure-data")
@limiter.limit("10/minute")
async def get_secure_data(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()),
):
    """Example protected endpoint with rate limiting"""
    payload = verify_token(credentials.credentials)
    require_role(payload, Roles.USER)
    return {
        "message": "Authenticated access granted",
        "user_id": payload.get("sub"),
        "role": payload.get("role"),
    }
