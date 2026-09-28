"""OIDC SSO tests — config gating, signed-state CSRF, and login-URL construction.

End-to-end sign-in requires a real OIDC provider (client credentials + IdP app), so these
tests cover everything that does not need a live IdP.
"""

import httpx
import pytest

from shadowportx.core.config import settings
from shadowportx.services import oidc


async def _client():
    from shadowportx.main import app
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def test_auth_config_default(seeded):
    async with await _client() as c:
        r = await c.get("/api/v1/auth/config")
        assert r.status_code == 200
        body = r.json()
        assert body["password"] is True and body["oidc_enabled"] is False


async def test_oidc_login_disabled_returns_404(seeded):
    async with await _client() as c:
        r = await c.get("/api/v1/auth/oidc/login")
        assert r.status_code == 404


def test_signed_state_roundtrip():
    token = oidc._sign_state("nonce-xyz")
    assert oidc._read_state(token) == "nonce-xyz"


def test_tampered_state_rejected():
    with pytest.raises(oidc.OIDCError):
        oidc._read_state("garbage.token.value")


async def test_build_login_url_from_discovery():
    settings.oidc_client_id = "client-123"
    settings.oidc_redirect_uri = "https://app/api/v1/auth/oidc/callback"
    settings.oidc_scopes = "openid email profile"
    oidc._discovery_cache = {"authorization_endpoint": "https://idp.example/authorize",
                             "issuer": "https://idp.example"}
    try:
        url = await oidc.build_login_url()
        assert url.startswith("https://idp.example/authorize?")
        assert "client_id=client-123" in url
        assert "response_type=code" in url
        assert "state=" in url and "nonce=" in url
        assert "redirect_uri=https" in url
    finally:
        oidc._discovery_cache = None
        settings.oidc_client_id = ""
        settings.oidc_redirect_uri = ""
