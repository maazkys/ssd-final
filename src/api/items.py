"""
Items API — demonstrates secure CRUD with ownership checks
OWASP ASVS V4.2 — Broken Object Level Authorization (BOLA) prevention
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address
import html
import structlog

from auth.jwt_handler import verify_token
from auth.rbac import require_role, Roles
from models.database import get_db
from models.item_model import ItemModel

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
logger = structlog.get_logger()
security = HTTPBearer()

MAX_ITEM_NAME_LEN = 100
MAX_DESCRIPTION_LEN = 1000


class ItemCreate(BaseModel):
    name: str
    description: str = ""

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, v):
        # Length check
        if len(v) > MAX_ITEM_NAME_LEN:
            raise ValueError(f"Name must be under {MAX_ITEM_NAME_LEN} characters")
        # HTML escape to prevent XSS if rendered in UI
        return html.escape(v.strip())

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, v):
        if len(v) > MAX_DESCRIPTION_LEN:
            raise ValueError(f"Description must be under {MAX_DESCRIPTION_LEN} characters")
        return html.escape(v.strip())


@router.post("/", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def create_item(
    request: Request,
    item: ItemCreate,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    payload = verify_token(credentials.credentials)
    new_item = await ItemModel.create(
        db,
        name=item.name,
        description=item.description,
        owner_id=payload["sub"],
    )
    logger.info("item_created", item_id=str(new_item.id), owner=payload["sub"])
    return {"id": str(new_item.id), "name": new_item.name}


@router.get("/{item_id}")
async def get_item(
    item_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    payload = verify_token(credentials.credentials)
    item = await ItemModel.get_by_id(db, item_id)

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    # BOLA prevention — only owner or admin can access
    if item.owner_id != payload["sub"] and payload.get("role") != Roles.ADMIN:
        logger.warning(
            "bola_attempt",
            accessor=payload["sub"],
            item_owner=item.owner_id,
            item_id=item_id,
        )
        # Return 404 not 403 — don't reveal item existence to unauthorized users
        raise HTTPException(status_code=404, detail="Item not found")

    return {"id": str(item.id), "name": item.name, "description": item.description}


@router.delete("/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_item(
    item_id: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    payload = verify_token(credentials.credentials)
    item = await ItemModel.get_by_id(db, item_id)

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    if item.owner_id != payload["sub"] and payload.get("role") != Roles.ADMIN:
        logger.warning("unauthorized_delete_attempt", user=payload["sub"], item_id=item_id)
        raise HTTPException(status_code=404, detail="Item not found")

    await ItemModel.delete(db, item_id)
    logger.info("item_deleted", item_id=item_id, deleted_by=payload["sub"])
