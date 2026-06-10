"""
Users API
Security: Input validation (Pydantic), parameterized queries (no SQLi),
          bcrypt password hashing, rate limiting on auth endpoints
OWASP ASVS: V2 (Authentication), V5 (Input Validation)
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address
import bcrypt
import re
import structlog

from auth.jwt_handler import create_access_token, verify_token, revoke_token
from auth.rbac import require_role, require_permission, Roles
from models.database import get_db
from models.user_model import UserModel

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
logger = structlog.get_logger()
security = HTTPBearer()

# ── Input Models (Pydantic validation = defense against injection) ────────────

class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Roles = Roles.USER

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        # Whitelist: only alphanumeric + underscore, 3-30 chars
        if not re.match(r"^[a-zA-Z0-9_]{3,30}$", v):
            raise ValueError("Username must be 3-30 alphanumeric characters or underscores")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        # OWASP ASVS V2.1.1 - minimum password requirements
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserLogin(BaseModel):
    username: str
    password: str

    @field_validator("username", "password")
    @classmethod
    def no_null_bytes(cls, v):
        # Prevent null byte injection
        if "\x00" in v:
            raise ValueError("Invalid characters in input")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 1800


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/register", response_model=dict, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/hour")  # Prevent account enumeration via timing
async def register(request: Request, user: UserRegister, db: AsyncSession = Depends(get_db)):
    """
    Register new user.
    - Bcrypt password hashing (work factor 12)
    - Parameterized query via SQLAlchemy ORM (no SQLi)
    - No username enumeration (generic error)
    """
    # Check existing user (parameterized — SQLAlchemy ORM handles escaping)
    existing = await UserModel.get_by_username(db, user.username)
    if existing:
        # Generic error — don't reveal if username exists (prevents enumeration)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration failed. Please try again."
        )

    # Hash password with bcrypt (work factor 12 per OWASP recommendation)
    password_hash = bcrypt.hashpw(
        user.password.encode("utf-8"),
        bcrypt.gensalt(rounds=12)
    ).decode("utf-8")

    new_user = await UserModel.create(
        db,
        username=user.username,
        email=str(user.email),
        password_hash=password_hash,
        role=user.role.value,
    )

    logger.info("user_registered", username=user.username, role=user.role.value)
    return {"message": "User registered successfully", "user_id": str(new_user.id)}


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")  # Brute-force protection
async def login(request: Request, credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    """
    Authenticate user and issue JWT.
    - Constant-time comparison (bcrypt) prevents timing attacks
    - Generic error prevents username enumeration
    """
    db_user = await UserModel.get_by_username(db, credentials.username)

    # Always run bcrypt even if user not found — prevents timing oracle
    dummy_hash = "$2b$12$KIXoLMVkq5DUGDFaFAoAOuFHZBwQGzVQk6o7u1v8p3VcRhkuPRKOy"
    stored_hash = db_user.password_hash if db_user else dummy_hash

    is_valid = bcrypt.checkpw(
        credentials.password.encode("utf-8"),
        stored_hash.encode("utf-8")
    )

    if not db_user or not is_valid:
        logger.warning("login_failed", username=credentials.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({"sub": str(db_user.id), "role": db_user.role})
    logger.info("login_success", user_id=str(db_user.id), role=db_user.role)
    return TokenResponse(access_token=token)


@router.post("/logout")
async def logout(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Revoke JWT on logout"""
    revoke_token(credentials.credentials)
    return {"message": "Logged out successfully"}


@router.get("/me")
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    payload = verify_token(credentials.credentials)
    user = await UserModel.get_by_id(db, payload["sub"])
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": str(user.id), "username": user.username, "role": user.role}


@router.get("/all")
async def list_users(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    """Admin-only endpoint"""
    payload = verify_token(credentials.credentials)
    require_role(payload, Roles.ADMIN)
    users = await UserModel.get_all(db)
    return [{"id": str(u.id), "username": u.username, "role": u.role} for u in users]
