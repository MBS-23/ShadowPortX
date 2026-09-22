"""Notification channel management (outbound webhook integrations)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context, require_manage
from shadowportx.db import models
from shadowportx.db.base import get_session
from shadowportx.services import notifications
from shadowportx.services import persistence as P

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_model=list[schemas.NotificationChannelOut])
async def list_channels(ctx: Context = Depends(get_context), session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(models.NotificationChannel).where(models.NotificationChannel.organization_id == ctx.org_id)
    )).scalars().all()
    return list(rows)


@router.post("", response_model=schemas.NotificationChannelOut, status_code=status.HTTP_201_CREATED)
async def add_channel(
    body: schemas.NotificationChannelIn,
    ctx: Context = Depends(require_manage),
    session: AsyncSession = Depends(get_session),
):
    ch = models.NotificationChannel(
        organization_id=ctx.org_id, name=body.name, kind=body.kind, url=body.url,
        min_severity=body.min_severity, enabled=body.enabled,
    )
    session.add(ch)
    await session.flush()
    await P.audit(session, ctx.org_id, "notification.added", body.name, kind=body.kind, actor=ctx.email)
    return ch


@router.post("/{channel_id}/test")
async def test_channel(
    channel_id: int,
    ctx: Context = Depends(require_manage),
    session: AsyncSession = Depends(get_session),
):
    ch = (await session.execute(
        select(models.NotificationChannel).where(
            models.NotificationChannel.id == channel_id,
            models.NotificationChannel.organization_id == ctx.org_id)
    )).scalar_one_or_none()
    if not ch:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")
    ok = await notifications.send_test(ch)
    return {"delivered": ok}


@router.delete("/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_channel(
    channel_id: int,
    ctx: Context = Depends(require_manage),
    session: AsyncSession = Depends(get_session),
):
    ch = (await session.execute(
        select(models.NotificationChannel).where(
            models.NotificationChannel.id == channel_id,
            models.NotificationChannel.organization_id == ctx.org_id)
    )).scalar_one_or_none()
    if not ch:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")
    await session.delete(ch)
