"""User ORM model"""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, select
from sqlalchemy.ext.asyncio import AsyncSession
from models.database import Base


class UserModel(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(30), unique=True, nullable=False, index=True)
    email = Column(String(254), unique=True, nullable=False)
    password_hash = Column(String(60), nullable=False)
    role = Column(String(20), nullable=False, default="user")
    created_at = Column(DateTime, default=datetime.utcnow)

    @classmethod
    async def get_by_username(cls, db: AsyncSession, username: str):
        result = await db.execute(select(cls).where(cls.username == username))
        return result.scalar_one_or_none()

    @classmethod
    async def get_by_id(cls, db: AsyncSession, user_id: str):
        result = await db.execute(select(cls).where(cls.id == user_id))
        return result.scalar_one_or_none()

    @classmethod
    async def get_all(cls, db: AsyncSession):
        result = await db.execute(select(cls))
        return result.scalars().all()

    @classmethod
    async def create(cls, db: AsyncSession, **kwargs):
        user = cls(**kwargs)
        db.add(user)
        await db.flush()
        return user
