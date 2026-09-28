"""Self-service registration tests — creation, least-privilege role, dedupe, validation, gating."""

import httpx

from shadowportx.core.config import settings


async def _client():
    from shadowportx.main import app
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_auth_config_reports_registration_flag(seeded):
    async with await _client() as c:
        r = await c.get("/api/v1/auth/config")
        assert r.status_code == 200
        assert r.json()["allow_self_registration"] is True


async def test_register_creates_least_privilege_account(seeded):
    async with await _client() as c:
        r = await c.post("/api/v1/auth/register", json={
            "email": "Analyst@Example.com", "password": "s3cure-pass", "full_name": "New User"})
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["access_token"]
        assert body["email"] == "analyst@example.com"   # normalized
        # An org already has the seeded admin, so a self-signup is least-privilege, not owner.
        assert body["role"] == "viewer"

        # The new credentials work end to end.
        login = await c.post("/api/v1/auth/login",
                             json={"email": "analyst@example.com", "password": "s3cure-pass"})
        assert login.status_code == 200
        me = await c.get("/api/v1/auth/me",
                         headers={"Authorization": f"Bearer {body['access_token']}"})
        assert me.status_code == 200 and me.json()["email"] == "analyst@example.com"


async def test_register_rejects_duplicate_email(seeded):
    async with await _client() as c:
        first = await c.post("/api/v1/auth/register",
                             json={"email": "dupe@example.com", "password": "s3cure-pass"})
        assert first.status_code == 201
        again = await c.post("/api/v1/auth/register",
                             json={"email": "dupe@example.com", "password": "different-pass"})
        assert again.status_code == 409


async def test_register_rejects_weak_password(seeded):
    async with await _client() as c:
        r = await c.post("/api/v1/auth/register",
                         json={"email": "weak@example.com", "password": "short"})
        assert r.status_code == 422


async def test_register_rejects_malformed_email(seeded):
    async with await _client() as c:
        r = await c.post("/api/v1/auth/register",
                         json={"email": "not-an-email", "password": "s3cure-pass"})
        assert r.status_code == 422


async def test_register_disabled_returns_403(seeded):
    settings.allow_self_registration = False
    try:
        async with await _client() as c:
            r = await c.post("/api/v1/auth/register",
                             json={"email": "blocked@example.com", "password": "s3cure-pass"})
            assert r.status_code == 403
    finally:
        settings.allow_self_registration = True
