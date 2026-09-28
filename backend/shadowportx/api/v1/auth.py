"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context
from shadowportx.core import enums
from shadowportx.core.config import settings
from shadowportx.core.security import create_access_token, hash_password, verify_password
from shadowportx.db import models
from shadowportx.db.base import get_session
from shadowportx.services import oidc
from shadowportx.services import persistence as P

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/config")
async def auth_config():
    """Public: lets the dashboard know which sign-in methods are available."""
    return {
        "password": True,  # nosec B105
        "oidc_enabled": settings.oidc_enabled,
        "oidc_button_label": settings.oidc_button_label,
        "allow_self_registration": settings.allow_self_registration,
    }


@router.post("/login", response_model=schemas.TokenResponse)
async def login(body: schemas.LoginRequest, session: AsyncSession = Depends(get_session)):
    email = body.email.strip().lower()
    user = (await session.execute(
        select(models.User).where(models.User.email == email, models.User.is_active.is_(True))
    )).scalar_one_or_none()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    await P.audit(session, user.organization_id, "auth.login", target=user.email,
                  actor=user.email, role=user.role.value)
    token = create_access_token(user.email, role=user.role.value, org_id=user.organization_id)
    return schemas.TokenResponse(
        access_token=token, role=user.role, email=user.email, org_id=user.organization_id
    )


@router.post("/register", response_model=schemas.TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: schemas.RegisterRequest, session: AsyncSession = Depends(get_session)):
    """Self-service account creation. Guarded by settings.allow_self_registration and
    least-privilege by default (first account in an empty org bootstraps as owner)."""
    if not settings.allow_self_registration:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Self-service registration is disabled")

    org = (await session.execute(
        select(models.Organization).where(models.Organization.slug == "default")
    )).scalar_one_or_none()
    if org is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "No organization configured")

    email = body.email  # normalized + validated by the schema
    existing = (await session.execute(
        select(models.User).where(models.User.organization_id == org.id, models.User.email == email)
    )).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")

    # Bootstrap the first account of an empty org as owner; all later self-signups are least-privilege.
    user_count = (await session.execute(
        select(func.count(models.User.id)).where(models.User.organization_id == org.id)
    )).scalar_one()
    role = enums.UserRole.OWNER if user_count == 0 else enums.UserRole(settings.self_registration_role)

    user = models.User(
        organization_id=org.id,
        email=email,
        full_name=(body.full_name or email.split("@")[0]).strip(),
        hashed_password=hash_password(body.password),
        role=role,
    )
    session.add(user)
    await session.flush()
    await P.audit(session, org.id, "auth.register", target=user.email,
                  actor=user.email, role=user.role.value)

    token = create_access_token(user.email, role=user.role.value, org_id=org.id)
    return schemas.TokenResponse(
        access_token=token, role=user.role, email=user.email, org_id=org.id
    )


@router.get("/me")
async def me(ctx: Context = Depends(get_context)):
    return {"email": ctx.email, "role": ctx.role, "org_id": ctx.org_id}


# --- SSO (OpenID Connect) ---
@router.get("/oidc/login")
async def oidc_login():
    if not settings.oidc_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO is not enabled")
    try:
        url = await oidc.build_login_url()
    except oidc.OIDCError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"SSO provider error: {exc}") from exc
    return RedirectResponse(url, status_code=status.HTTP_302_FOUND)


@router.get("/oidc/callback")
async def oidc_callback(
    code: str, state: str, session: AsyncSession = Depends(get_session)
):
    if not settings.oidc_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO is not enabled")
    try:
        claims = await oidc.exchange_and_validate(code, state)
    except oidc.OIDCError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"SSO sign-in failed: {exc}") from exc

    email = (claims.get("email") or "").lower()
    if not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "SSO token has no email claim")
    if settings.oidc_allowed_domain and not email.endswith("@" + settings.oidc_allowed_domain.lower()):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Email domain is not permitted")

    org = (await session.execute(
        select(models.Organization).where(models.Organization.slug == "default")
    )).scalar_one_or_none()
    if org is None:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "No organization configured")

    user = (await session.execute(
        select(models.User).where(models.User.organization_id == org.id, models.User.email == email)
    )).scalar_one_or_none()
    if user is None:
        user = models.User(
            organization_id=org.id, email=email,
            full_name=claims.get("name") or email.split("@")[0],
            hashed_password=hash_password("!sso-no-password-" + email),  # SSO users don't log in by password
            role=enums.UserRole(settings.oidc_default_role),
        )
        session.add(user)
        await session.flush()

    token = create_access_token(user.email, role=user.role.value, org_id=org.id)
    base = settings.oidc_post_login_redirect or "/"
    # Token in the URL fragment: never sent to servers or written to access logs.
    return RedirectResponse(f"{base}#spx_token={token}", status_code=status.HTTP_302_FOUND)
