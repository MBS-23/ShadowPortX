"""Finding validation — SAFE, non-destructive confirmation of a suspected finding.

Safety levels:
* L0 detection, L1 passive, L2 non-destructive active verification  -> IMPLEMENTED (used here)
* L3 proof-of-concept, L4 controlled exploitation                    -> NOT ENABLED (by design)

This engine only re-runs the existing read-only verification checks to observe whether a
security condition actually exists. It never exploits, writes, deletes, or persists on a
target. Findings that would require L3/L4 to confirm are marked ``needs_verification`` with
a clear message — we never fake a confirmation.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import utcnow
from shadowportx.engines import verification

_OBSERVED_CATEGORIES = {
    enums.FindingCategory.MISSING_SECURITY_HEADER,
    enums.FindingCategory.TLS_WEAKNESS,
    enums.FindingCategory.SERVICE_MISCONFIGURATION,
}


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

    def _finish(validated, state, message, condition=None, evidence=None):
        finding.state = state
        finding.validated_at = utcnow()
        if evidence:
            finding.evidence = {**(finding.evidence or {}),
                                "validation": {**evidence, "condition": condition,
                                               "method": "non-destructive verification (L2)"}}
        return {
            "finding_id": finding.id, "spx_id": finding.spx_id, "validated": validated,
            "state": finding.state, "condition": condition, "severity": finding.severity,
            "confidence": finding.confidence, "evidence": (evidence or {}), "message": message,
        }

    # Findings already established by direct observation (headers/TLS/verification) re-affirm.
    if finding.state == enums.FindingState.CONFIRMED and finding.category in _OBSERVED_CATEGORIES:
        return _finish(True, enums.FindingState.CONFIRMED,
                       "Already confirmed by direct observation; re-affirmed.",
                       condition="already-observed")

    # Safe active validation (L2) via the verification engine.
    if service_name and port:
        vres = await verification.run_verification(service_name, host, int(port), application=application)
        if vres and vres.verified and vres.severity != enums.Severity.INFO:
            return _finish(True, enums.FindingState.CONFIRMED,
                           "Security condition confirmed via non-destructive verification.",
                           condition=vres.condition, evidence=vres.evidence)
        if vres and vres.verified:
            return _finish(False, enums.FindingState.NEEDS_VERIFICATION,
                           "Service reachable but no security-critical condition auto-confirmed. "
                           "Manual verification recommended.", condition=vres.condition,
                           evidence=vres.evidence)

    return _finish(
        False, enums.FindingState.NEEDS_VERIFICATION,
        "No non-destructive validator applies to this finding. Controlled proof-of-concept (L3) "
        "and exploitation (L4) are not enabled; verify manually within the authorized scope.",
    )
