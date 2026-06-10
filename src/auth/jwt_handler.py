"""
JWT Handler - Secure token management
Covers: OWASP ASVS V3 (Session Management), JWT best practices
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from fastapi import HTTPException, status
import structlog

logger = structlog.get_logger()

# ── Config (loaded from Vault/env in prod) ───────────────────────────────────
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY must be set — never hardcode secrets!")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Token blacklist (use Redis in prod for distributed systems)
_revoked_tokens: set = set()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a signed JWT with expiry and issued-at claims.
    OWASP ASVS V3.5.1 - Token contains minimal necessary claims.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": "secureapp-mvp",           # Issuer claim
        "aud": "secureapp-clients",        # Audience claim
    })

    encoded = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.info("token_created", subject=data.get("sub"), expires=expire.isoformat())
    return encoded


def verify_token(token: str) -> dict:
    """
    Validates JWT signature, expiry, issuer, and audience.
    Raises 401 on any failure — no info leakage.
    OWASP ASVS V3.5.2, V3.5.3
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Check revocation list
    if token in _revoked_tokens:
        logger.warning("revoked_token_used")
        raise credentials_exception

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            audience="secureapp-clients",
            issuer="secureapp-mvp",
        )
        subject: str = payload.get("sub")
        if subject is None:
            raise credentials_exception
        return payload

    except JWTError as e:
        logger.warning("jwt_validation_failed", error=str(e))
        raise credentials_exception


def revoke_token(token: str) -> None:
    """Revoke a token (logout). In prod: store in Redis with TTL = token expiry."""
    _revoked_tokens.add(token)
    logger.info("token_revoked")
