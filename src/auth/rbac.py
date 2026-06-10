"""
Role-Based Access Control (RBAC)
Maps to: OWASP ASVS V4, NIST CSF PR.AC, Zero Trust Principle of Least Privilege
"""

from enum import Enum
from fastapi import HTTPException, status
import structlog

logger = structlog.get_logger()


class Roles(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    USER = "user"
    READONLY = "readonly"


# Role hierarchy: higher index = more privilege
ROLE_HIERARCHY = [Roles.READONLY, Roles.USER, Roles.ANALYST, Roles.ADMIN]

# Fine-grained permission matrix (ABAC layer)
PERMISSIONS = {
    Roles.ADMIN:    {"read", "write", "delete", "manage_users", "view_audit_logs"},
    Roles.ANALYST:  {"read", "write", "view_audit_logs"},
    Roles.USER:     {"read", "write"},
    Roles.READONLY: {"read"},
}


def require_role(token_payload: dict, minimum_role: Roles) -> None:
    """
    Enforce minimum role requirement.
    Logs authorization failures for SIEM ingestion.
    """
    user_role_str = token_payload.get("role", "")

    try:
        user_role = Roles(user_role_str)
    except ValueError:
        logger.warning("authz_failed_invalid_role", role=user_role_str)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    user_level = ROLE_HIERARCHY.index(user_role) if user_role in ROLE_HIERARCHY else -1
    required_level = ROLE_HIERARCHY.index(minimum_role)

    if user_level < required_level:
        logger.warning(
            "authz_failed_insufficient_role",
            user_role=user_role,
            required_role=minimum_role,
            subject=token_payload.get("sub"),
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


def require_permission(token_payload: dict, permission: str) -> None:
    """Fine-grained permission check (ABAC layer)"""
    user_role_str = token_payload.get("role", "")
    try:
        user_role = Roles(user_role_str)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    if permission not in PERMISSIONS.get(user_role, set()):
        logger.warning(
            "authz_permission_denied",
            permission=permission,
            role=user_role,
            subject=token_payload.get("sub"),
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
