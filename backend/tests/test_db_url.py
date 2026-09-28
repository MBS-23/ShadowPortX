"""Database URL normalization — accept a pasted managed-Postgres URL and drive asyncpg + SSL."""

from shadowportx.db.base import _prepare_engine_url


def test_sqlite_passthrough():
    url, ca = _prepare_engine_url("sqlite+aiosqlite:///./var/x.db")
    assert url.startswith("sqlite")
    assert ca == {"check_same_thread": False}


def test_neon_url_upgraded_and_ssl_enabled():
    url, ca = _prepare_engine_url(
        "postgresql://user:pw@ep-cool-name.us-east-2.aws.neon.tech/neondb?sslmode=require")
    assert url.startswith("postgresql+asyncpg://")
    assert "sslmode" not in url
    assert ca.get("ssl") is True


def test_postgres_scheme_variant_and_channel_binding_stripped():
    url, ca = _prepare_engine_url(
        "postgres://u:pw@host/db?sslmode=require&channel_binding=require")
    assert url.startswith("postgresql+asyncpg://")
    assert "channel_binding" not in url and "sslmode" not in url
    assert ca["ssl"] is True


def test_local_postgres_no_ssl():
    url, ca = _prepare_engine_url("postgresql+asyncpg://shadowportx:shadowportx@postgres:5432/shadowportx")
    assert url == "postgresql+asyncpg://shadowportx:shadowportx@postgres:5432/shadowportx"
    assert "ssl" not in ca
