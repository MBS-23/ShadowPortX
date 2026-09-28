"""OpenID Connect (OIDC) SSO — standards-based, provider-agnostic.

Implements the authorization-code flow against any OIDC provider (Google, Okta, Auth0,
Azure AD, Keycloak, …) via the provider's discovery document. CSRF is prevented with a
signed, short-lived ``state`` (no server-side session store needed), and the ID token is
verified against the provider's JWKS (signature, issuer, audience, expiry, nonce).
"""

from __future__ import annotations

import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from shadowportx.core.config import settings

_TIMEOUT = 10.0
_discovery_cache: dict | None = None
_jwks_cache: dict | None = None


class OIDCError(RuntimeError):
    """Raised for any OIDC configuration or verification failure."""


async def _discovery() -> dict:
    global _discovery_cache
    if _discovery_cache is None:
        url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(url)
        if r.status_code >= 400:
            raise OIDCError(f"discovery failed ({r.status_code})")
        _discovery_cache = r.json()
    return _discovery_cache


async def _jwks(refresh: bool = False) -> dict:
    global _jwks_cache
    if _jwks_cache is None or refresh:
        disc = await _discovery()
        async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
            r = await c.get(disc["jwks_uri"])
        if r.status_code >= 400:
            raise OIDCError("JWKS fetch failed")
        _jwks_cache = r.json()
    return _jwks_cache


def _sign_state(nonce: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"nonce": nonce, "purpose": "oidc", "iat": now, "exp": now + 600},
        settings.secret_key, algorithm="HS256",
    )


def _read_state(state: str) -> str:
    try:
        data = jwt.decode(state, settings.secret_key, algorithms=["HS256"],
                          options={"require": ["exp", "iat"]})
    except jwt.PyJWTError as exc:
        raise OIDCError(f"invalid state: {exc}") from exc
    if data.get("purpose") != "oidc":
        raise OIDCError("invalid state purpose")
    return data["nonce"]


async def build_login_url() -> str:
    disc = await _discovery()
    nonce = secrets.token_urlsafe(16)
    params = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "scope": settings.oidc_scopes,
        "state": _sign_state(nonce),
        "nonce": nonce,
    }
    return f"{disc['authorization_endpoint']}?{urlencode(params)}"


def _key_for(header: dict, jwks: dict):
    for jwk in jwks.get("keys", []):
        if jwk.get("kid") == header.get("kid"):
            kty = jwk.get("kty")
            return ECAlgorithm.from_jwk(jwk) if kty == "EC" else RSAAlgorithm.from_jwk(jwk)
    return None


async def exchange_and_validate(code: str, state: str) -> dict:
    """Exchange the auth code and return verified ID-token claims."""
    nonce = _read_state(state)
    disc = await _discovery()

    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        tok = await c.post(
            disc["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.oidc_redirect_uri,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
            },
            headers={"Accept": "application/json"},
        )
    if tok.status_code >= 400:
        raise OIDCError(f"token exchange failed ({tok.status_code})")
    id_token = tok.json().get("id_token")
    if not id_token:
        raise OIDCError("no id_token returned")

    header = jwt.get_unverified_header(id_token)
    key = _key_for(header, await _jwks())
    if key is None:  # key rotation — refresh once
        key = _key_for(header, await _jwks(refresh=True))
    if key is None:
        raise OIDCError("no matching JWKS signing key")

    claims = jwt.decode(
        id_token, key, algorithms=[header.get("alg", "RS256")],
        audience=settings.oidc_client_id, issuer=disc.get("issuer", settings.oidc_issuer),
        options={"require": ["exp", "iat"]},
    )
    if claims.get("nonce") != nonce:
        raise OIDCError("nonce mismatch")
    return claims
