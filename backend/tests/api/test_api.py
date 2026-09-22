"""API tests via httpx ASGITransport (single event loop -> no aiosqlite cross-loop issues)."""

import httpx


async def _client():
    from shadowportx.main import app
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


async def test_health(seeded):
    async with await _client() as c:
        r = await c.get("/health")
        assert r.status_code == 200 and r.json()["status"] == "ok"


async def test_overview_and_scope(seeded):
    async with await _client() as c:
        assert (await c.get("/api/v1/overview")).status_code == 200
        scope = await c.get("/api/v1/scope")
        assert scope.status_code == 200 and len(scope.json()) >= 1


async def test_login_success_and_failure(seeded):
    async with await _client() as c:
        ok = await c.post("/api/v1/auth/login",
                          json={"email": "admin@shadowportx.local", "password": "shadowportx"})
        assert ok.status_code == 200 and ok.json()["role"] == "admin"
        bad = await c.post("/api/v1/auth/login",
                           json={"email": "admin@shadowportx.local", "password": "wrong"})
        assert bad.status_code == 401


async def test_scan_out_of_scope_rejected(seeded):
    async with await _client() as c:
        r = await c.post("/api/v1/scans", json={"target": "8.8.8.8", "ports": "80"})
        assert r.status_code == 403
        assert "scope" in r.json()["detail"].lower()
