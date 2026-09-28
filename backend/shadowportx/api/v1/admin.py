"""Admin console — platform-wide visibility for owners/admins.

Answers "who is using this platform and what are they doing": user roster with
derived last-activity, adoption/usage counters, and a recent-activity feed sourced
from the audit log. Read-only; every route requires a management role.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, require_manage
from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import get_session, utcnow

router = APIRouter(prefix="/admin", tags=["admin"])


async def _last_active_map(session: AsyncSession, org_id: int) -> dict[str, object]:
    """Most recent audit timestamp per actor (their last observed activity)."""
    rows = (await session.execute(
        select(models.AuditLog.actor, func.max(models.AuditLog.ts))
        .where(models.AuditLog.organization_id == org_id)
        .group_by(models.AuditLog.actor)
    )).all()
    return dict(rows)


def _to_admin_user(u: models.User, last_active: dict) -> schemas.AdminUser:
    return schemas.AdminUser(
        id=u.id, email=u.email, full_name=u.full_name, role=u.role,
        is_active=u.is_active, created_at=u.created_at,
        last_active_at=last_active.get(u.email),
    )


@router.get("/overview", response_model=schemas.AdminOverview)
async def admin_overview(
    ctx: Context = Depends(require_manage),
    session: AsyncSession = Depends(get_session),
):
    org = ctx.org_id
    since = utcnow() - timedelta(days=7)
    U, S, F, A, L = (models.User, models.Scan, models.Finding, models.Asset, models.AuditLog)

    users = (await session.execute(select(U).where(U.organization_id == org))).scalars().all()
    by_role: dict[str, int] = {}
    for u in users:
        by_role[u.role.value] = by_role.get(u.role.value, 0) + 1

    async def _count(stmt) -> int:
        return int((await session.execute(stmt)).scalar_one() or 0)

    # Time-window filters run in the DB (avoids SQLite naive/aware datetime comparisons in Python).
    new_7d = await _count(select(func.count(U.id)).where(
        U.organization_id == org, U.created_at >= since))
    logins_7d = await _count(select(func.count(L.id)).where(
        L.organization_id == org, L.action == "auth.login", L.ts >= since))
    scans_total = await _count(select(func.count(S.id)).where(S.organization_id == org))
    scans_active = await _count(select(func.count(S.id)).where(
        S.organization_id == org,
        S.status.in_([enums.ScanStatus.QUEUED, enums.ScanStatus.RUNNING])))
    findings_total = await _count(select(func.count(F.id)).where(F.organization_id == org))
    open_findings = await _count(select(func.count(F.id)).where(
        F.organization_id == org, F.status != enums.FindingStatus.RESOLVED))
    assets_total = await _count(select(func.count(A.id)).where(A.organization_id == org))

    last_active = await _last_active_map(session, org)
    recent_signups = sorted(users, key=lambda u: u.created_at or datetime.min, reverse=True)[:5]
    activity_rows = (await session.execute(
        select(L).where(L.organization_id == org).order_by(desc(L.ts)).limit(12)
    )).scalars().all()

    return schemas.AdminOverview(
        users_total=len(users),
        users_active=sum(1 for u in users if u.is_active),
        users_by_role=by_role,
        new_users_7d=new_7d,
        logins_7d=logins_7d,
        scans_total=scans_total,
        scans_active=scans_active,
        findings_total=findings_total,
        open_findings=open_findings,
        assets_total=assets_total,
        recent_signups=[_to_admin_user(u, last_active) for u in recent_signups],
        recent_activity=[
            schemas.AdminActivity(actor=a.actor, action=a.action, target=a.target, ts=a.ts)
            for a in activity_rows
        ],
    )


@router.get("/users", response_model=list[schemas.AdminUser])
async def admin_users(
    ctx: Context = Depends(require_manage),
    session: AsyncSession = Depends(get_session),
):
    users = (await session.execute(
        select(models.User).where(models.User.organization_id == ctx.org_id)
        .order_by(models.User.created_at)
    )).scalars().all()
    last_active = await _last_active_map(session, ctx.org_id)
    return [_to_admin_user(u, last_active) for u in users]


@router.get("/activity", response_model=list[schemas.AdminActivity])
async def admin_activity(
    ctx: Context = Depends(require_manage),
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=50, ge=1, le=200),
):
    rows = (await session.execute(
        select(models.AuditLog).where(models.AuditLog.organization_id == ctx.org_id)
        .order_by(desc(models.AuditLog.ts)).limit(limit)
    )).scalars().all()
    return [
        schemas.AdminActivity(actor=a.actor, action=a.action, target=a.target, ts=a.ts)
        for a in rows
    ]
