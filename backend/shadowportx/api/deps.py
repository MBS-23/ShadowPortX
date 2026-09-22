"""Shared API dependencies: DB session, authenticated context, and role guards."""

from __future__ import annotations

from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx.core import enums
from shadowportx.core.config import settings
from shadowportx.core.security import decode_token
from shadowportx.db import models
from shadowportx.db.base import get_session

_bearer = HTTPBearer(auto_error=False)


@dataclass
class Context:
    org_id: int
    role: enums.UserRole
    email: str


async def _default_org_id(session: AsyncSession) -> int | None:
    org = (await session.execute(
        select(models.Organization).where(models.Organization.slug == "default")
    )).scalar_one_or_none()
    return org.id if org else None


async def get_context(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: AsyncSession = Depends(get_session),
) -> Context:
    """Resolve the caller's org + role.

    With a valid Bearer token, use its claims. In debug mode, fall back to the default org
    with ADMIN role so the dashboard is usable without login friction. In production, a
    token is required.
    """
    if creds and creds.credentials:
        try:
            payload = decode_token(creds.credentials)
        except jwt.PyJWTError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {exc}") from exc
        return Context(
            org_id=int(payload["org"]),
            role=enums.UserRole(payload.get("role", "viewer")),
            email=str(payload["sub"]),
        )

    if settings.debug:
        org_id = await _default_org_id(session)
        if org_id is not None:
            return Context(org_id=org_id, role=enums.UserRole.ADMIN, email="dev@localhost")

    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")


def require_scan(ctx: Context = Depends(get_context)) -> Context:
    if not ctx.role.can_scan:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role cannot start scans")
    return ctx


def require_manage(ctx: Context = Depends(get_context)) -> Context:
    if not ctx.role.can_manage:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Your role cannot manage this resource")
    return ctx
