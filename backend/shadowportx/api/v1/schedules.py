"""Scheduled scans — continuous attack-surface monitoring."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context, require_scan
from shadowportx.core import scope
from shadowportx.core.config import settings
from shadowportx.db import models
from shadowportx.db.base import get_session, utcnow
from shadowportx.services import persistence as P
from shadowportx.services.pipeline import _load_scope

router = APIRouter(prefix="/schedules", tags=["schedules"])


@router.get("", response_model=list[schemas.ScheduleOut])
async def list_schedules(ctx: Context = Depends(get_context), session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(models.Schedule).where(models.Schedule.organization_id == ctx.org_id)
        .order_by(desc(models.Schedule.id))
    )).scalars().all()
    return list(rows)


@router.post("", response_model=schemas.ScheduleOut, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    body: schemas.ScheduleIn,
    ctx: Context = Depends(require_scan),
    session: AsyncSession = Depends(get_session),
):
    target = body.target.strip().lower().rstrip(".")
    rules = await _load_scope(session, ctx.org_id)
    decision = scope.evaluate(target, rules, enforce=settings.enforce_scope)
    if not decision.allowed:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Target out of scope: {decision.reason}")

    sched = models.Schedule(
        organization_id=ctx.org_id, target=target, interval_minutes=body.interval_minutes,
        ports=body.ports, subdomains=body.subdomains, enabled=body.enabled,
        next_run_at=utcnow() + timedelta(minutes=body.interval_minutes),
    )
    session.add(sched)
    await session.flush()
    await P.audit(session, ctx.org_id, "schedule.created", target,
                  interval_minutes=body.interval_minutes, actor=ctx.email)
    return sched


@router.post("/{schedule_id}/toggle", response_model=schemas.ScheduleOut)
async def toggle_schedule(
    schedule_id: int, ctx: Context = Depends(require_scan), session: AsyncSession = Depends(get_session)
):
    sched = (await session.execute(
        select(models.Schedule).where(models.Schedule.id == schedule_id,
                                      models.Schedule.organization_id == ctx.org_id)
    )).scalar_one_or_none()
    if not sched:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    sched.enabled = not sched.enabled
    if sched.enabled and not sched.next_run_at:
        sched.next_run_at = utcnow() + timedelta(minutes=sched.interval_minutes)
    return sched


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: int, ctx: Context = Depends(require_scan), session: AsyncSession = Depends(get_session)
):
    sched = (await session.execute(
        select(models.Schedule).where(models.Schedule.id == schedule_id,
                                      models.Schedule.organization_id == ctx.org_id)
    )).scalar_one_or_none()
    if not sched:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    await session.delete(sched)
