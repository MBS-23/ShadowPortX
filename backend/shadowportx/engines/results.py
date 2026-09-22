"""Plain data-transfer objects shared between engines.

These are intentionally decoupled from the ORM: engines produce dataclasses, and a
persistence layer maps them onto DB rows. This keeps engines pure and testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from shadowportx.core import enums


@dataclass
class ServiceInfo:
    name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    confidence: enums.Confidence = enums.Confidence.MEDIUM
    detection_method: enums.DetectionMethod = enums.DetectionMethod.PORT_STATE
    verified: bool = False
    evidence: dict = field(default_factory=dict)


@dataclass
class PortResult:
    host: str
    port: int
    protocol: enums.Protocol = enums.Protocol.TCP
    state: enums.PortState = enums.PortState.OPEN
    latency_ms: float | None = None
    banner: str | None = None
    service: ServiceInfo | None = None


@dataclass
class TechInfo:
    name: str
    category: str | None = None
    version: str | None = None
    cpe: str | None = None
    confidence: enums.Confidence = enums.Confidence.MEDIUM
    evidence: list[str] = field(default_factory=list)


@dataclass
class CertInfo:
    subject: str | None = None
    issuer: str | None = None
    serial: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    sans: list[str] = field(default_factory=list)
    signature_algorithm: str | None = None
    key_bits: int | None = None
    tls_versions: list[str] = field(default_factory=list)
    is_valid: bool = True
    fingerprint_sha256: str | None = None
    days_until_expiry: int | None = None


@dataclass
class HttpInfo:
    url: str
    status_code: int | None = None
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    server: str | None = None
    title: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, bool] = field(default_factory=dict)
    technologies: list[TechInfo] = field(default_factory=list)
    cookies: list[str] = field(default_factory=list)


@dataclass
class ReconResult:
    target: str
    resolved_ips: list[str] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)
    whois: dict = field(default_factory=dict)
    asn: str | None = None


@dataclass
class VerificationResult:
    """Outcome of a non-destructive service-level verification check."""

    service: str
    verified: bool
    condition: str | None = None       # e.g. "no-auth-required"
    severity: enums.Severity = enums.Severity.INFO
    confidence: enums.Confidence = enums.Confidence.MEDIUM
    evidence: dict = field(default_factory=dict)
    recommendation: str | None = None


@dataclass
class CorrelatedVuln:
    cve_id: str
    cvss_score: float | None
    severity: enums.Severity
    description: str | None
    cpe_match: str | None
    exploit_known: bool = False
    references: list[str] = field(default_factory=list)
