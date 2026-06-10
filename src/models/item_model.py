"""Item ORM model"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from models.database import Base


class ItemModel(Base):
    __tablename__ = "items"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100), nullable=False)
    description = Column(String(1000), default="")
    owner_id = Column(String(36), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    @classmethod
    async def create(cls, db: AsyncSession, **kwargs):
        item = cls(**kwargs)
        db.add(item)
        await db.flush()
        return item

    @classmethod
    async def get_by_id(cls, db: AsyncSession, item_id: str):
        result = await db.execute(select(cls).where(cls.id == item_id))
        return result.scalar_one_or_none()

    @classmethod
    async def delete(cls, db: AsyncSession, item_id: str):
        await db.execute(delete(cls).where(cls.id == item_id))
