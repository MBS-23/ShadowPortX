"""Async SQLAlchemy engine, session factory, and declarative base.

Uses SQLAlchemy 2.0 async style. The same code path serves SQLite (local, zero-setup)
and PostgreSQL (Docker/prod) purely by swapping ``SPX_DATABASE_URL``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from shadowportx.core.config import settings


def utcnow() -> datetime:
    """Naive UTC timestamp.

    All timestamp columns are ``TIMESTAMP WITHOUT TIME ZONE`` and hold UTC. We store naive
    UTC so the same value inserts cleanly on both SQLite and PostgreSQL — asyncpg rejects an
    aware datetime for a tz-naive column ("can't subtract offset-naive and offset-aware").
    Every datetime in the app is UTC by construction, so this stays unambiguous.
    """
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    """Declarative base with common id + timestamp columns for every table."""

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


# Engine / session factory -----------------------------------------------------
def _prepare_engine_url(raw: str) -> tuple[str, dict]:
    """Normalize the configured database URL for async SQLAlchemy.

    Accepts a plain Postgres URL exactly as pasted from a managed provider (Neon / Render /
    Supabase): it upgrades the scheme to ``postgresql+asyncpg`` and translates libpq-style
    SSL query params (``sslmode`` / ``channel_binding``) — which asyncpg rejects in the URL —
    into an asyncpg ``ssl`` connect arg. SQLite is returned unchanged. This makes "paste the
    connection string into SPX_DATABASE_URL" just work.
    """
    if raw.startswith("sqlite"):
        return raw, {"check_same_thread": False}

    for prefix in ("postgresql+asyncpg://", "postgresql://", "postgres://"):
        if raw.startswith(prefix):
            raw = "postgresql+asyncpg://" + raw[len(prefix):]
            break

    parts = urlsplit(raw)
    query = dict(parse_qsl(parts.query))
    ssl_required = False
    for key in ("sslmode", "ssl", "channel_binding"):
        val = query.pop(key, None)
        if key in ("sslmode", "ssl") and val and val.lower() not in (
            "disable", "false", "0", "allow", "prefer"
        ):
            ssl_required = True
    clean = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

    connect_args: dict = {}
    if ssl_required:
        connect_args["ssl"] = True
    return clean, connect_args


_engine_url, _connect_args = _prepare_engine_url(settings.database_url)

engine = create_async_engine(
    _engine_url,
    echo=False,
    future=True,
    connect_args=_connect_args,
    pool_pre_ping=not settings.is_sqlite,
)

SessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


# Enforce foreign keys on SQLite (off by default) so cascades behave like Postgres.
if settings.is_sqlite:

    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, _record):  # pragma: no cover - driver glue
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a request-scoped session."""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Context-manager session for engines/workers running outside a request."""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create all tables. For MVP/dev we use create_all; Alembic handles prod migrations."""
    # Import models so they register on Base.metadata before create_all.
    from shadowportx.db import models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
