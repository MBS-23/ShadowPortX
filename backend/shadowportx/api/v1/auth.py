"""Authentication endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context
from shadowportx.core.security import create_access_token, verify_password
from shadowportx.db import models
from shadowportx.db.base import get_session

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=schemas.TokenResponse)
async def login(body: schemas.LoginRequest, session: AsyncSession = Depends(get_session)):
    user = (await session.execute(
        select(models.User).where(models.User.email == body.email, models.User.is_active.is_(True))
    )).scalar_one_or_none()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    token = create_access_token(user.email, role=user.role.value, org_id=user.organization_id)
    return schemas.TokenResponse(
        access_token=token, role=user.role, email=user.email, org_id=user.organization_id
    )


@router.get("/me")
async def me(ctx: Context = Depends(get_context)):
    return {"email": ctx.email, "role": ctx.role, "org_id": ctx.org_id}
