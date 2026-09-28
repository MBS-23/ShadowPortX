"""Upsert helpers mapping engine dataclasses onto ORM rows.

Kept separate from the pipeline so persistence is reusable and testable. All functions
take an ``AsyncSession`` and flush (not commit) — the caller owns the transaction.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import utcnow
from shadowportx.engines.correlation.finding import FindingDraft
from shadowportx.engines.results import CertInfo, CorrelatedVuln, ServiceInfo, TechInfo


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        return False


def exposure_for_ip(ip: str | None) -> enums.Exposure:
    if not ip:
        return enums.Exposure.INTERNET_FACING
    return enums.Exposure.INTERNET_FACING if is_public_ip(ip) else enums.Exposure.INTERNAL


async def get_or_create_org(session: AsyncSession, name: str, slug: str) -> models.Organization:
    org = (await session.execute(select(models.Organization).where(models.Organization.slug == slug))).scalar_one_or_none()
    if org:
        return org
    org = models.Organization(name=name, slug=slug)
    session.add(org)
    await session.flush()
    return org


async def upsert_asset(
    session: AsyncSession,
    org_id: int,
    asset_type: enums.AssetType,
    value: str,
    *,
    ip_address: str | None = None,
    exposure: enums.Exposure | None = None,
    parent_id: int | None = None,
    is_known: bool = True,
) -> tuple[models.Asset, bool]:
    stmt = select(models.Asset).where(
        models.Asset.organization_id == org_id,
        models.Asset.type == asset_type,
        models.Asset.value == value,
    )
    asset = (await session.execute(stmt)).scalar_one_or_none()
    created = False
    if asset is None:
        asset = models.Asset(
            organization_id=org_id, type=asset_type, value=value,
            status=enums.AssetStatus.ACTIVE,
            exposure=exposure or exposure_for_ip(ip_address),
            ip_address=ip_address, parent_id=parent_id, is_known=is_known,
        )
        session.add(asset)
        created = True
    else:
        asset.last_seen = utcnow()
        asset.status = enums.AssetStatus.ACTIVE
        if ip_address:
            asset.ip_address = ip_address
        if exposure:
            asset.exposure = exposure
    await session.flush()
    return asset, created


async def upsert_port(
    session: AsyncSession, asset_id: int, number: int, protocol: enums.Protocol, state: enums.PortState
) -> tuple[models.Port, bool]:
    stmt = select(models.Port).where(
        models.Port.asset_id == asset_id, models.Port.number == number, models.Port.protocol == protocol
    )
    port = (await session.execute(stmt)).scalar_one_or_none()
    created = False
    if port is None:
        port = models.Port(asset_id=asset_id, number=number, protocol=protocol, state=state)
        session.add(port)
        created = True
    else:
        port.state = state
        port.last_seen = utcnow()
    await session.flush()
    return port, created


async def upsert_service(session: AsyncSession, port_id: int, info: ServiceInfo) -> models.Service:
    stmt = select(models.Service).where(models.Service.port_id == port_id)
    svc = (await session.execute(stmt)).scalars().first()
    if svc is None:
        svc = models.Service(port_id=port_id)
        session.add(svc)
    svc.name = info.name
    svc.product = info.product
    svc.version = info.version
    svc.cpe = info.cpe
    svc.confidence = info.confidence
    svc.detection_method = info.detection_method
    svc.verified = info.verified
    svc.evidence = info.evidence
    svc.last_seen = utcnow()
    await session.flush()
    return svc


async def upsert_technology(session: AsyncSession, asset_id: int, tech: TechInfo) -> models.Technology:
    stmt = select(models.Technology).where(
        models.Technology.asset_id == asset_id, models.Technology.name == tech.name
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        row = models.Technology(asset_id=asset_id, name=tech.name)
        session.add(row)
    row.category = tech.category
    row.version = tech.version
    row.cpe = tech.cpe
    row.confidence = tech.confidence
    row.evidence = tech.evidence
    row.last_seen = utcnow()
    await session.flush()
    return row


async def upsert_certificate(session: AsyncSession, asset_id: int, cert: CertInfo) -> models.Certificate:
    def _dt(v: str | None) -> datetime | None:
        if not v:
            return None
        try:
            return datetime.fromisoformat(v)
        except ValueError:
            return None

    stmt = select(models.Certificate).where(models.Certificate.asset_id == asset_id)
    row = (await session.execute(stmt)).scalars().first()
    if row is None:
        row = models.Certificate(asset_id=asset_id)
        session.add(row)
    row.subject = cert.subject
    row.issuer = cert.issuer
    row.serial = cert.serial
    row.not_before = _dt(cert.not_before)
    row.not_after = _dt(cert.not_after)
    row.sans = cert.sans
    row.signature_algorithm = cert.signature_algorithm
    row.key_bits = cert.key_bits
    row.tls_versions = cert.tls_versions
    row.is_valid = cert.is_valid
    row.fingerprint_sha256 = cert.fingerprint_sha256
    row.last_seen = utcnow()
    await session.flush()
    return row


async def upsert_vulnerability(session: AsyncSession, cve: CorrelatedVuln) -> models.Vulnerability:
    stmt = select(models.Vulnerability).where(models.Vulnerability.cve_id == cve.cve_id)
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        row = models.Vulnerability(cve_id=cve.cve_id)
        session.add(row)
    row.title = cve.description
    row.cvss_score = cve.cvss_score
    row.severity = cve.severity
    row.cpes = [cve.cpe_match] if cve.cpe_match else []
    row.references = cve.references
    row.exploit_known = cve.exploit_known
    await session.flush()
    return row


async def next_spx_id(session: AsyncSession) -> str:
    year = utcnow().year
    count = (await session.execute(select(func.count(models.Finding.id)))).scalar_one()
    return f"SPX-{year}-{count + 1:05d}"


async def upsert_finding(
    session: AsyncSession, org_id: int, asset_id: int, draft: FindingDraft, service_id: int | None,
    vuln_id: int | None,
) -> tuple[models.Finding, bool]:
    """Upsert by fingerprint. Returns (finding, created)."""
    stmt = select(models.Finding).where(
        models.Finding.organization_id == org_id, models.Finding.fingerprint == draft.fingerprint
    )
    finding = (await session.execute(stmt)).scalar_one_or_none()
    created = False
    if finding is None:
        finding = models.Finding(
            spx_id=await next_spx_id(session),
            organization_id=org_id,
            asset_id=asset_id,
            fingerprint=draft.fingerprint,
            status=enums.FindingStatus.NEW,
        )
        session.add(finding)
        created = True
    else:
        finding.last_seen = utcnow()
        # A previously resolved finding that reappears is reopened.
        if finding.status == enums.FindingStatus.RESOLVED:
            finding.status = enums.FindingStatus.NEW
            finding.resolved_at = None

    finding.service_id = service_id
    finding.vulnerability_id = vuln_id
    finding.title = draft.title
    finding.category = draft.category
    finding.severity = draft.severity
    finding.confidence = draft.confidence
    finding.state = draft.state
    finding.exposure = draft.exposure
    finding.detection_method = draft.detection_method
    finding.description = draft.description
    finding.recommendation = draft.recommendation
    finding.evidence = draft.evidence
    finding.references = draft.references
    finding.risk_score = draft.risk_score
    finding.risk_breakdown = draft.risk_breakdown
    await session.flush()
    return finding, created


async def audit(session: AsyncSession, org_id: int | None, action: str, target: str | None = None,
                actor: str = "system", **detail):
    session.add(models.AuditLog(organization_id=org_id, action=action, target=target,
                                actor=actor, detail=detail))
    await session.flush()
