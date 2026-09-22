"""ShadowPortX Exposure Score (SPX-ES) — contextual risk prioritization.

Deliberately NOT called CVSS. CVSS measures a vulnerability's intrinsic severity; SPX-ES
answers "what should this organization fix first?" by combining severity with *context*:

    SPX-ES = 100 * Σ (weightᵢ · factorᵢ)   over the factors below, then optional modifiers.

    factor            meaning                                        source
    ---------------------------------------------------------------------------
    severity          normalized CVSS / qualitative severity         0..1
    exposure          internet-facing > limited > internal           0..1
    criticality       business criticality of the asset              0..1
    confidence        detection confidence                           0..1
    exploit_intel     public exploit / KEV known                     0..1
    verification      was a security condition actually observed     0..1

Weights are configurable (see core/config.py) and sum to 1.0 by default. A "recently
exposed" modifier adds urgency to brand-new attack-surface changes. Output is clamped to
[0, 100] and mapped to a priority band. The full breakdown is returned for transparency —
the dashboard shows *why* a score is what it is.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shadowportx.core import enums
from shadowportx.core.config import settings

_EXPOSURE_FACTOR = {
    enums.Exposure.INTERNET_FACING: 1.0,
    enums.Exposure.LIMITED: 0.6,
    enums.Exposure.INTERNAL: 0.3,
}
_CRITICALITY_FACTOR = {
    enums.Criticality.CRITICAL: 1.0,
    enums.Criticality.HIGH: 0.8,
    enums.Criticality.MEDIUM: 0.55,
    enums.Criticality.LOW: 0.3,
    enums.Criticality.UNKNOWN: 0.5,
}
_STATE_FACTOR = {
    enums.FindingState.CONFIRMED: 1.0,
    enums.FindingState.NEEDS_VERIFICATION: 0.65,
    enums.FindingState.POTENTIALLY_AFFECTED: 0.6,
    enums.FindingState.DETECTED: 0.5,
}


@dataclass
class ExposureScore:
    score: float
    priority: enums.Severity
    breakdown: dict = field(default_factory=dict)


def priority_for(score: float) -> enums.Severity:
    if score >= 90:
        return enums.Severity.CRITICAL
    if score >= 70:
        return enums.Severity.HIGH
    if score >= 40:
        return enums.Severity.MEDIUM
    if score > 0:
        return enums.Severity.LOW
    return enums.Severity.INFO


def compute_exposure_score(
    *,
    severity: enums.Severity,
    cvss_score: float | None = None,
    exposure: enums.Exposure = enums.Exposure.INTERNET_FACING,
    criticality: enums.Criticality = enums.Criticality.UNKNOWN,
    confidence: enums.Confidence = enums.Confidence.MEDIUM,
    exploit_known: bool = False,
    state: enums.FindingState = enums.FindingState.DETECTED,
    recently_exposed: bool = False,
) -> ExposureScore:
    # severity factor: prefer real CVSS when present, else qualitative rank/4.
    sev_factor = (cvss_score / 10.0) if cvss_score is not None else (severity.rank / 4.0)
    sev_factor = max(0.0, min(1.0, sev_factor))

    factors = {
        "severity": (sev_factor, settings.risk_weight_severity),
        "exposure": (_EXPOSURE_FACTOR.get(exposure, 0.6), settings.risk_weight_exposure),
        "criticality": (_CRITICALITY_FACTOR.get(criticality, 0.5), settings.risk_weight_criticality),
        "confidence": (confidence.factor, settings.risk_weight_confidence),
        "exploit_intel": (1.0 if exploit_known else 0.3, settings.risk_weight_exploit_intel),
        "verification": (_STATE_FACTOR.get(state, 0.5), settings.risk_weight_verification),
    }

    base = sum(value * weight for value, weight in factors.values()) * 100.0

    modifier = 0.0
    if recently_exposed:
        modifier += 5.0  # brand-new exposure gets a small urgency bump

    score = max(0.0, min(100.0, base + modifier))

    breakdown = {
        name: {"factor": round(value, 3), "weight": weight, "contribution": round(value * weight * 100, 2)}
        for name, (value, weight) in factors.items()
    }
    breakdown["modifiers"] = {"recently_exposed": modifier}
    breakdown["formula"] = "SPX-ES = 100 * Σ(weight·factor) + modifiers"

    return ExposureScore(score=round(score, 1), priority=priority_for(score), breakdown=breakdown)
