"""
Database configuration and session management.
"""
from contextlib import asynccontextmanager
import json
from typing import Any, AsyncGenerator
from uuid import UUID

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    pass


def _json_default(o: Any) -> str:
    """JSON fallback used when serializing JSONB payloads (UUIDs, enums, ...)."""
    if isinstance(o, UUID):
        return str(o)
    if hasattr(o, "value"):
        return o.value
    return str(o)


def _json_serializer(obj: Any) -> str:
    return json.dumps(obj, default=_json_default)


def create_engine() -> AsyncEngine:
    return create_async_engine(
        settings.DATABASE_URL,
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        pool_timeout=settings.DATABASE_POOL_TIMEOUT,
        pool_pre_ping=True,
        echo=settings.DEBUG,
        json_serializer=_json_serializer,
    )


engine = create_engine()

async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database tables."""
    from app.models import Base as ModelsBase
    async with engine.begin() as conn:
        await conn.run_sync(ModelsBase.metadata.create_all)
        # The project currently bootstraps from metadata rather than shipping
        # Alembic revisions.  Keep existing installations compatible with the
        # evidence-backed vendor cache while a formal migration is prepared.
        if conn.dialect.name == "postgresql":
            await conn.execute(text(
                "ALTER TABLE assets ADD COLUMN IF NOT EXISTS vendor VARCHAR(128)"
            ))


async def close_db() -> None:
    """Close database connections."""
    await engine.dispose()
