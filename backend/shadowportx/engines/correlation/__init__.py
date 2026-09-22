"""Correlation engine — assembles scan/recon/intel/verification signals into findings."""

from shadowportx.engines.correlation.finding import (
    FindingDraft,
    finding_for_exposed_service,
    finding_for_verification,
    findings_for_cves,
    findings_for_http,
    findings_for_tls,
)

__all__ = [
    "FindingDraft",
    "findings_for_cves",
    "findings_for_http",
    "findings_for_tls",
    "finding_for_exposed_service",
    "finding_for_verification",
]
