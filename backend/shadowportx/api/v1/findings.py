"""Findings endpoints: list/filter, detail, lifecycle updates, and remediation re-verify."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context, require_scan
from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import get_session
from shadowportx.services import persistence as P
from shadowportx.worker import job_manager

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=list[schemas.FindingOut])
async def list_findings(
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
    severity: enums.Severity | None = None,
    status_: enums.FindingStatus | None = None,
    category: enums.FindingCategory | None = None,
    asset_id: int | None = None,
    limit: int = 300,
):
    stmt = select(models.Finding).where(models.Finding.organization_id == ctx.org_id)
    if severity:
        stmt = stmt.where(models.Finding.severity == severity)
    if status_:
        stmt = stmt.where(models.Finding.status == status_)
    if category:
        stmt = stmt.where(models.Finding.category == category)
    if asset_id:
        stmt = stmt.where(models.Finding.asset_id == asset_id)
    stmt = stmt.order_by(desc(models.Finding.risk_score)).limit(limit)
    return list((await session.execute(stmt)).scalars().all())


@router.get("/{finding_id}", response_model=schemas.FindingDetail)
async def get_finding(
    finding_id: int,
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    finding = (await session.execute(
        select(models.Finding).where(
            models.Finding.id == finding_id, models.Finding.organization_id == ctx.org_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return finding


@router.patch("/{finding_id}", response_model=schemas.FindingDetail)
async def update_finding(
    finding_id: int,
    body: schemas.FindingUpdate,
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    finding = (await session.execute(
        select(models.Finding).where(
            models.Finding.id == finding_id, models.Finding.organization_id == ctx.org_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    data = body.model_dump(exclude_none=True)
    if "status" in data:
        finding.status = data["status"]
        if data["status"] == enums.FindingStatus.RESOLVED:
            from shadowportx.db.base import utcnow
            finding.resolved_at = utcnow()
    if "assignee" in data:
        finding.assignee = data["assignee"]
    if "team" in data:
        finding.team = data["team"]
    if "notes" in data:
        finding.notes = data["notes"]
    await P.audit(session, ctx.org_id, "finding.updated", finding.spx_id, changes=data, actor=ctx.email)
    return finding


@router.post("/{finding_id}/validate", response_model=schemas.ValidationResult)
async def validate_finding_endpoint(
    finding_id: int,
    ctx: Context = Depends(require_scan),
    session: AsyncSession = Depends(get_session),
):
    """Safe, non-destructive validation of a finding (Levels 0–2). Confirms a security
    condition via read-only verification, or marks it needs-verification. L3/L4 not enabled."""
    finding = (await session.execute(
        select(models.Finding).where(
            models.Finding.id == finding_id, models.Finding.organization_id == ctx.org_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    from shadowportx.services.validation import validate_finding
    result = await validate_finding(session, finding)
    await P.audit(session, ctx.org_id, "finding.validated", finding.spx_id,
                  validated=result["validated"], actor=ctx.email)
    return result


@router.post("/{finding_id}/verify", response_model=schemas.ScanOut, status_code=status.HTTP_201_CREATED)
async def verify_finding(
    finding_id: int,
    ctx: Context = Depends(require_scan),
    session: AsyncSession = Depends(get_session),
):
    """Remediation re-verification: enqueue a fresh scan of the finding's asset.

    The pipeline re-checks the asset; if the condition is gone, the finding auto-resolves
    and the asset's risk score drops — the Detection → Remediation → Validation loop.
    """
    finding = (await session.execute(
        select(models.Finding).where(
            models.Finding.id == finding_id, models.Finding.organization_id == ctx.org_id)
    )).scalar_one_or_none()
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    asset = (await session.execute(
        select(models.Asset).where(models.Asset.id == finding.asset_id)
    )).scalar_one_or_none()
    if not asset:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")

    finding.status = enums.FindingStatus.VERIFYING
    scan = models.Scan(
        organization_id=ctx.org_id, target=asset.value, scan_type=enums.ScanType.VERIFY,
        status=enums.ScanStatus.QUEUED,
        config={"ports": "top1000", "subdomains": False}, stats={},
    )
    session.add(scan)
    await session.flush()
    scan_id = scan.id
    await session.commit()
    job_manager.submit(scan_id)
    return scan
