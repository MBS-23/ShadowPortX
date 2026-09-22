"""Scan endpoints: create (enqueue), list, get, cancel."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context, require_scan
from shadowportx.core import enums, scope
from shadowportx.core.config import settings
from shadowportx.db import models
from shadowportx.db.base import get_session
from shadowportx.services.pipeline import _load_scope
from shadowportx.worker import job_manager

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=schemas.ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    body: schemas.ScanCreate,
    ctx: Context = Depends(require_scan),
    session: AsyncSession = Depends(get_session),
):
    target = body.target.strip().lower().rstrip(".")
    if not target:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Target is required")

    # Pre-flight scope check so the caller gets immediate feedback.
    rules = await _load_scope(session, ctx.org_id)
    decision = scope.evaluate(target, rules, enforce=settings.enforce_scope)
    if not decision.allowed:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"Target out of scope: {decision.reason}")

    config = {
        "ports": body.ports or settings.scan_default_ports,
        "technique": (body.technique or enums.ScanType.TCP_CONNECT).value,
        "subdomains": body.subdomains,
    }
    if body.concurrency:
        config["concurrency"] = body.concurrency
    if body.rate_limit is not None:
        config["rate_limit"] = body.rate_limit

    scan = models.Scan(
        organization_id=ctx.org_id, target=target, scan_type=body.scan_type,
        status=enums.ScanStatus.QUEUED, config=config, stats={},
    )
    session.add(scan)
    await session.flush()
    scan_id = scan.id
    await session.commit()

    job_manager.submit(scan_id)
    return scan


@router.get("", response_model=list[schemas.ScanOut])
async def list_scans(
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
    limit: int = 50,
):
    rows = (await session.execute(
        select(models.Scan).where(models.Scan.organization_id == ctx.org_id)
        .order_by(desc(models.Scan.id)).limit(limit)
    )).scalars().all()
    return list(rows)


@router.get("/{scan_id}", response_model=schemas.ScanOut)
async def get_scan(
    scan_id: int,
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    scan = (await session.execute(
        select(models.Scan).where(models.Scan.id == scan_id, models.Scan.organization_id == ctx.org_id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


@router.post("/{scan_id}/cancel", response_model=schemas.ScanOut)
async def cancel_scan(
    scan_id: int,
    ctx: Context = Depends(require_scan),
    session: AsyncSession = Depends(get_session),
):
    scan = (await session.execute(
        select(models.Scan).where(models.Scan.id == scan_id, models.Scan.organization_id == ctx.org_id)
    )).scalar_one_or_none()
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    if scan.status in (enums.ScanStatus.QUEUED, enums.ScanStatus.RUNNING):
        scan.status = enums.ScanStatus.CANCELLED
    return scan


@router.get("/{scan_a}/compare/{scan_b}", response_model=schemas.ScanDiff)
async def compare_scans(
    scan_a: int,
    scan_b: int,
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    async def _get(sid: int) -> models.Scan:
        s = (await session.execute(
            select(models.Scan).where(models.Scan.id == sid, models.Scan.organization_id == ctx.org_id)
        )).scalar_one_or_none()
        if not s:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"Scan {sid} not found")
        return s

    a, b = await _get(scan_a), await _get(scan_b)
    keys = ("open_ports", "services", "findings", "new_findings", "resolved_findings",
            "subdomains", "asset_risk")
    delta = {k: (b.stats.get(k, 0) or 0) - (a.stats.get(k, 0) or 0) for k in keys}
    return schemas.ScanDiff(
        scan_a=a.id, scan_b=b.id, target=b.target, delta=delta,
        a_stats=a.stats or {}, b_stats=b.stats or {},
    )
