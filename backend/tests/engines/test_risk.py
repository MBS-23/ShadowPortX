from shadowportx.core import enums
from shadowportx.engines.risk import compute_exposure_score, priority_for


def test_context_raises_score():
    high = compute_exposure_score(
        severity=enums.Severity.CRITICAL, cvss_score=9.8,
        exposure=enums.Exposure.INTERNET_FACING, criticality=enums.Criticality.CRITICAL,
        confidence=enums.Confidence.HIGH, exploit_known=True, state=enums.FindingState.CONFIRMED)
    low = compute_exposure_score(
        severity=enums.Severity.CRITICAL, cvss_score=9.8,
        exposure=enums.Exposure.INTERNAL, criticality=enums.Criticality.LOW,
        confidence=enums.Confidence.MEDIUM, exploit_known=False, state=enums.FindingState.DETECTED)
    assert high.score > low.score
    assert high.priority == enums.Severity.CRITICAL


def test_score_bounds():
    s = compute_exposure_score(
        severity=enums.Severity.INFO, cvss_score=0.0, exposure=enums.Exposure.INTERNAL,
        criticality=enums.Criticality.LOW, confidence=enums.Confidence.LOW)
    assert 0.0 <= s.score <= 100.0


def test_priority_bands():
    assert priority_for(95) == enums.Severity.CRITICAL
    assert priority_for(75) == enums.Severity.HIGH
    assert priority_for(50) == enums.Severity.MEDIUM
    assert priority_for(10) == enums.Severity.LOW
    assert priority_for(0) == enums.Severity.INFO


def test_breakdown_is_transparent():
    s = compute_exposure_score(severity=enums.Severity.HIGH, confidence=enums.Confidence.HIGH)
    assert "severity" in s.breakdown and "formula" in s.breakdown
    assert s.breakdown["severity"]["contribution"] >= 0
