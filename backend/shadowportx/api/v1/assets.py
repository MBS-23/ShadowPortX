"""Asset inventory endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from shadowportx import schemas
from shadowportx.api.deps import Context, get_context
from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import get_session

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=list[schemas.AssetOut])
async def list_assets(
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
    type: enums.AssetType | None = None,
    known: bool | None = None,
    limit: int = 200,
):
    stmt = select(models.Asset).where(models.Asset.organization_id == ctx.org_id)
    if type:
        stmt = stmt.where(models.Asset.type == type)
    if known is not None:
        stmt = stmt.where(models.Asset.is_known.is_(known))
    stmt = stmt.order_by(desc(models.Asset.risk_score), desc(models.Asset.last_seen)).limit(limit)
    return list((await session.execute(stmt)).scalars().all())


@router.get("/{asset_id}", response_model=schemas.AssetDetail)
async def get_asset(
    asset_id: int,
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    stmt = (
        select(models.Asset)
        .where(models.Asset.id == asset_id, models.Asset.organization_id == ctx.org_id)
        .options(
            selectinload(models.Asset.ports).selectinload(models.Port.services),
            selectinload(models.Asset.technologies),
            selectinload(models.Asset.certificates),
        )
    )
    asset = (await session.execute(stmt)).scalar_one_or_none()
    if not asset:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    return asset


@router.patch("/{asset_id}", response_model=schemas.AssetDetail)
async def update_asset(
    asset_id: int,
    body: schemas.AssetUpdate,
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    stmt = (
        select(models.Asset)
        .where(models.Asset.id == asset_id, models.Asset.organization_id == ctx.org_id)
        .options(
            selectinload(models.Asset.ports).selectinload(models.Port.services),
            selectinload(models.Asset.technologies),
            selectinload(models.Asset.certificates),
        )
    )
    asset = (await session.execute(stmt)).scalar_one_or_none()
    if not asset:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(asset, field, value)
    return asset
