"""Admin console tests — role gating, user roster, usage stats, activity feed.

Tests run with SPX_DEBUG defaulting on, so an unauthenticated request resolves to the
default-org admin (dev fallback). To prove the management-role guard, we pass a real
viewer token and assert it is refused.
"""

import httpx


async def _client():
    from shadowportx.main import app
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_admin_overview_ok(seeded):
    async with await _client() as c:
        r = await c.get("/api/v1/admin/overview")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["users_total"] >= 1
        assert "admin" in body["users_by_role"]
        for key in ("scans_total", "findings_total", "assets_total", "logins_7d"):
            assert key in body


async def test_admin_users_lists_seeded_admin(seeded):
    async with await _client() as c:
        r = await c.get("/api/v1/admin/users")
        assert r.status_code == 200
        emails = [u["email"] for u in r.json()]
        assert "admin@shadowportx.local" in emails


async def test_admin_forbidden_for_viewer(seeded):
    async with await _client() as c:
        reg = await c.post("/api/v1/auth/register",
                           json={"email": "viewer1@example.com", "password": "s3cure-pass"})
        assert reg.status_code == 201 and reg.json()["role"] == "viewer"
        token = reg.json()["access_token"]
        r = await c.get("/api/v1/admin/overview", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403


async def test_admin_activity_records_auth_events(seeded):
    async with await _client() as c:
        await c.post("/api/v1/auth/login",
                     json={"email": "admin@shadowportx.local", "password": "shadowportx"})
        r = await c.get("/api/v1/admin/activity")
        assert r.status_code == 200
        actions = [a["action"] for a in r.json()]
        assert "auth.login" in actions


async def test_admin_can_promote_viewer_to_analyst(seeded):
    async with await _client() as c:
        reg = await c.post("/api/v1/auth/register",
                           json={"email": "promote@example.com", "password": "s3cure-pass"})
        assert reg.status_code == 201 and reg.json()["role"] == "viewer"
        users = (await c.get("/api/v1/admin/users")).json()
        uid = next(u["id"] for u in users if u["email"] == "promote@example.com")
        r = await c.patch(f"/api/v1/admin/users/{uid}", json={"role": "analyst"})
        assert r.status_code == 200 and r.json()["role"] == "analyst"


async def test_admin_can_deactivate_user(seeded):
    async with await _client() as c:
        await c.post("/api/v1/auth/register",
                     json={"email": "deact@example.com", "password": "s3cure-pass"})
        users = (await c.get("/api/v1/admin/users")).json()
        uid = next(u["id"] for u in users if u["email"] == "deact@example.com")
        r = await c.patch(f"/api/v1/admin/users/{uid}", json={"is_active": False})
        assert r.status_code == 200 and r.json()["is_active"] is False


async def test_admin_cannot_change_own_role(seeded):
    async with await _client() as c:
        login = await c.post("/api/v1/auth/login",
                             json={"email": "admin@shadowportx.local", "password": "shadowportx"})
        token = login.json()["access_token"]
        hdr = {"Authorization": f"Bearer {token}"}
        users = (await c.get("/api/v1/admin/users", headers=hdr)).json()
        uid = next(u["id"] for u in users if u["email"] == "admin@shadowportx.local")
        r = await c.patch(f"/api/v1/admin/users/{uid}", json={"role": "viewer"}, headers=hdr)
        assert r.status_code == 400


async def test_non_owner_cannot_grant_owner(seeded):
    async with await _client() as c:
        await c.post("/api/v1/auth/register",
                     json={"email": "grant@example.com", "password": "s3cure-pass"})
        users = (await c.get("/api/v1/admin/users")).json()  # debug fallback = admin (not owner)
        uid = next(u["id"] for u in users if u["email"] == "grant@example.com")
        r = await c.patch(f"/api/v1/admin/users/{uid}", json={"role": "owner"})
        assert r.status_code == 403


async def test_admin_update_forbidden_for_viewer(seeded):
    async with await _client() as c:
        reg = await c.post("/api/v1/auth/register",
                           json={"email": "v2@example.com", "password": "s3cure-pass"})
        token = reg.json()["access_token"]
        r = await c.patch("/api/v1/admin/users/1", json={"role": "admin"},
                          headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403
