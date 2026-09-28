"""Finding validation — SAFE, non-destructive confirmation of a suspected finding.

Safety levels:
* L0 detection, L1 passive, L2 non-destructive active verification   -> IMPLEMENTED
* L3 SAFE proof-of-concept (read-only, benign probes, human-triggered) -> IMPLEMENTED
* L4 weaponized / automated exploitation                              -> NOT IMPLEMENTED (by design)

This engine only issues read-only checks to observe whether a security condition actually
exists. It never exploits, writes, deletes, brute-forces, or persists on a target, and it is
only ever invoked by an explicit, scope-checked user action (never by the scheduler). Findings
that would require weaponized exploitation (L4) to confirm are left ``needs_verification`` with a
clear message — we never fabricate a confirmation.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx.core import enums, scope
from shadowportx.core.config import settings
from shadowportx.db import models
from shadowportx.db.base import utcnow
from shadowportx.engines import verification
from shadowportx.engines.verification import safe_poc

_OBSERVED_CATEGORIES = {
    enums.FindingCategory.MISSING_SECURITY_HEADER,
    enums.FindingCategory.TLS_WEAKNESS,
    enums.FindingCategory.SERVICE_MISCONFIGURATION,
}


async def _in_scope(session: AsyncSession, org_id: int, host: str) -> scope.ScopeDecision:
    rules = [
        scope.ScopeRuleData(kind=r.kind, target_type=r.target_type, value=r.value)
        for r in (await session.execute(
            select(models.ScopeRule).where(models.ScopeRule.organization_id == org_id)
        )).scalars().all()
    ]
    return scope.evaluate(host, rules, enforce=settings.enforce_scope)


async def _web_port_for(session: AsyncSession, finding: models.Finding, port: int | None) -> int | None:
    if port and int(port) in safe_poc.WEB_PORTS:
        return int(port)
    ports = (await session.execute(
        select(models.Port).where(models.Port.asset_id == finding.asset_id)
    )).scalars().all()
    for pr in ports:
        if pr.number in safe_poc.WEB_PORTS:
            return pr.number
    return None


async def validate_finding(session: AsyncSession, finding: models.Finding) -> dict:
    asset = (await session.execute(
        select(models.Asset).where(models.Asset.id == finding.asset_id))).scalar_one()
    host = asset.value

    service_name, port, application = None, None, None
    if finding.service_id:
        svc = (await session.execute(
            select(models.Service).where(models.Service.id == finding.service_id))).scalar_one_or_none()
        if svc:
            service_name = svc.name
            application = (svc.evidence or {}).get("application")
            portrow = (await session.execute(
                select(models.Port).where(models.Port.id == svc.port_id))).scalar_one_or_none()
            if portrow:
                port = portrow.number
    if port is None:
        port = (finding.evidence or {}).get("port")

    def _finish(validated, state, message, condition=None, evidence=None,
                method="non-destructive verification (L2)"):
        finding.state = state
        finding.validated_at = utcnow()
        if evidence:
            finding.evidence = {**(finding.evidence or {}),
                                "validation": {**evidence, "condition": condition, "method": method}}
        return {
            "finding_id": finding.id, "spx_id": finding.spx_id, "validated": validated,
            "state": finding.state, "condition": condition, "severity": finding.severity,
            "confidence": finding.confidence, "evidence": (evidence or {}), "message": message,
        }

    # Guardrail: never probe a target outside the authorized scope, even on an explicit action.
    decision = await _in_scope(session, finding.organization_id, host)
    if not decision.allowed:
        return {
            "finding_id": finding.id, "spx_id": finding.spx_id, "validated": False,
            "state": finding.state, "condition": "out-of-scope", "severity": finding.severity,
            "confidence": finding.confidence, "evidence": {},
            "message": f"Validation not run — {decision.reason}",
        }

    # Findings already established by direct observation (headers/TLS/verification) re-affirm.
    if finding.state == enums.FindingState.CONFIRMED and finding.category in _OBSERVED_CATEGORIES:
        return _finish(True, enums.FindingState.CONFIRMED,
                       "Already confirmed by direct observation; re-affirmed.",
                       condition="already-observed")

    # Safe active validation (L2) via the service verification engine.
    if service_name and port:
        vres = await verification.run_verification(service_name, host, int(port), application=application)
        if vres and vres.verified and vres.severity != enums.Severity.INFO:
            return _finish(True, enums.FindingState.CONFIRMED,
                           "Security condition confirmed via non-destructive verification.",
                           condition=vres.condition, evidence=vres.evidence)

    # Safe proof-of-concept (L3): read-only, benign web probes for web-exposed findings.
    web_port = await _web_port_for(session, finding, port)
    if web_port is not None:
        poc = await safe_poc.run_safe_poc(host, int(web_port))
        confirmed = [r for r in poc if r.verified and r.severity != enums.Severity.INFO]
        if confirmed:
            strongest = max(confirmed, key=lambda r: r.severity.rank)
            evidence = {**strongest.evidence, "all_conditions": [r.condition for r in confirmed]}
            return _finish(
                True, enums.FindingState.CONFIRMED,
                f"Exposure confirmed via safe proof-of-concept ({strongest.condition}).",
                condition=strongest.condition, evidence=evidence,
                method="safe proof-of-concept (L3, read-only)",
            )

    return _finish(
        False, enums.FindingState.NEEDS_VERIFICATION,
        "No non-destructive check confirmed this finding. Weaponized exploitation (L4) is not "
        "enabled — verify manually with dedicated tooling within the authorized scope.",
    )
