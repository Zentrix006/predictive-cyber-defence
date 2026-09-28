from contextlib import asynccontextmanager
import asyncio
import logging
from typing import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

log = logging.getLogger("demo.db")

engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_size=10)

async_session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

_DB_READY = False


def db_ready() -> bool:
    return _DB_READY


async def init_db() -> None:
    """Best-effort demo schema initialization.

    The demo must stay alive even if Postgres is briefly restarting or the
    schema already exists from a previous run. We therefore retry connection
    establishment a few times and treat duplicate-object DDL as non-fatal.
    """
    global _DB_READY
    from sqlalchemy.exc import DBAPIError, ProgrammingError
    from app.core.database import Base

    last_error = None
    for attempt in range(1, 6):
        try:
            async with engine.begin() as conn:
                await conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{settings.DEMO_SCHEMA}"'))
                try:
                    await conn.run_sync(Base.metadata.create_all)
                except (ProgrammingError, DBAPIError) as exc:
                    msg = str(exc).lower()
                    if any(token in msg for token in ("already exists", "duplicate", "does not exist")):
                        log.warning("Demo schema bootstrap hit a non-fatal DDL conflict: %s", exc)
                    else:
                        raise
            await _migrations()
            _DB_READY = True
            return
        except Exception as exc:
            last_error = exc
            _DB_READY = False
            log.warning("Demo DB init attempt %s/5 failed: %s", attempt, exc)
            if attempt < 5:
                await asyncio.sleep(min(2.5, 0.5 * attempt))
    log.error("Demo DB init failed; continuing in degraded mode: %s", last_error)


async def _migrations() -> None:
    """Idempotent migrations for the kept-alive `demo` schema.

    The demo schema is not recreated on every start (participant/device state
    persists across restarts), so new enum members and columns introduced by
    the dynamic discovery revision are applied here. Every statement runs in
    its own transaction: PostgreSQL rejects mixing ALTER TYPE ... ADD VALUE
    with other DDL in one transaction, so one failed statement must never
    roll the rest back.
    """
    statements = [
        # Extend role enums with the device roles from the discovery revision.
        # Try schema-qualified and bare (public) type names; only one matches.
        "ALTER TYPE demo.demo_asset_role ADD VALUE IF NOT EXISTS 'client'",
        "ALTER TYPE demo_asset_role ADD VALUE IF NOT EXISTS 'client'",
        "ALTER TYPE demo.demo_asset_role ADD VALUE IF NOT EXISTS 'other'",
        "ALTER TYPE demo_asset_role ADD VALUE IF NOT EXISTS 'other'",
        "ALTER TYPE demo.demo_participant_role ADD VALUE IF NOT EXISTS 'client'",
        "ALTER TYPE demo_participant_role ADD VALUE IF NOT EXISTS 'client'",
        "ALTER TYPE demo.demo_participant_role ADD VALUE IF NOT EXISTS 'other'",
        "ALTER TYPE demo_participant_role ADD VALUE IF NOT EXISTS 'other'",
        # Device page endpoint recorded at registration/heartbeat time
        "ALTER TABLE demo.demo_assets ADD COLUMN IF NOT EXISTS page_endpoint VARCHAR(512) NULL",
        # Multi-actor tracking: which actor the prediction belongs to
        "ALTER TABLE demo.demo_predictions ADD COLUMN IF NOT EXISTS actor_id VARCHAR(32) NULL",
    ]
    for statement in statements:
        try:
            async with engine.begin() as conn:
                await conn.execute(text(statement))
        except Exception:
            # Type/column may already exist, or the type may live in another
            # schema — each statement is committed independently above.
            pass


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
