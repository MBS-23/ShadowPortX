"""Test configuration.

Points the platform at an isolated temp SQLite DB *before* any shadowportx import, so
tests never touch the dev database. Provides async DB and seed fixtures.
"""

import os
import tempfile

# Must be set before importing shadowportx (settings are cached at import).
_TEST_DB = os.path.join(tempfile.gettempdir(), "spx_test.db")
for _ext in ("", "-wal", "-shm"):
    try:
        os.remove(_TEST_DB + _ext)
    except OSError:
        pass
os.environ["SPX_DATABASE_URL"] = f"sqlite+aiosqlite:///{_TEST_DB}"
os.environ["SPX_SECRET_KEY"] = "test-secret-key-at-least-32-bytes-long-000"
os.environ["SPX_ENFORCE_SCOPE"] = "true"

import pytest_asyncio  # noqa: E402


@pytest_asyncio.fixture
async def db():
    """Ensure schema exists (create_all is idempotent) and dispose after the test.

    Disposing per test releases aiosqlite connections so the next test's event loop
    starts clean (pytest-asyncio uses a fresh loop per test in auto mode).
    """
    from shadowportx.db.base import engine, init_db
    await init_db()
    yield
    await engine.dispose()


@pytest_asyncio.fixture
async def seeded(db):
    """Seed default org + scope + admin, return org info."""
    from shadowportx.services.seed import seed
    return await seed()
