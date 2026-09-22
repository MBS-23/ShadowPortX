"""Shared enumerations used across models, schemas, and engines.

Kept as plain `str` enums so they serialize cleanly to JSON and persist as text
in both SQLite and PostgreSQL without custom types.
"""

from __future__ import annotations

from enum import StrEnum


class AssetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"


class AssetStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"


class Criticality(StrEnum):
    """Business criticality of an asset (drives risk contextualization)."""

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(StrEnum):
    UNKNOWN = "unknown"
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


class ScanType(StrEnum):
    TCP_CONNECT = "tcp_connect"
    TCP_SYN = "tcp_syn"
    UDP = "udp"
    SERVICE = "service"           # port + service/version detection
    FULL = "full"                 # recon + ports + services + verify + correlate
    RECON = "recon"               # dns/subdomain/whois/tls/http only
    VERIFY = "verify"             # remediation re-check of existing findings


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"           # target outside authorized scope


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @classmethod
    def from_cvss(cls, score: float | None) -> Severity:
        """Map a CVSS base score to a qualitative severity (CVSS v3.1 bands)."""
        if score is None:
            return cls.INFO
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def factor(self) -> float:
        return {"low": 0.5, "medium": 0.75, "high": 1.0}[self.value]


class DetectionMethod(StrEnum):
    """How a fact was established — central to evidence-based findings.

    The brief's key distinction: DETECTED (we saw a version) is not the same as
    POTENTIALLY_AFFECTED (public intel exists) is not the same as VERIFIED
    (a specific security condition was actually observed).
    """

    PORT_STATE = "port_state"
    BANNER = "banner"
    PROTOCOL_FINGERPRINT = "protocol_fingerprint"
    HTTP_HEADER = "http_header"
    TLS_CERTIFICATE = "tls_certificate"
    SERVICE_VERIFICATION = "service_verification"
    CVE_CORRELATION = "cve_correlation"
    DNS = "dns"


class FindingCategory(StrEnum):
    EXPOSED_SERVICE = "exposed_service"
    MISSING_SECURITY_HEADER = "missing_security_header"
    TLS_WEAKNESS = "tls_weakness"
    VULNERABILITY_INTELLIGENCE = "vulnerability_intelligence"
    SERVICE_MISCONFIGURATION = "service_misconfiguration"
    OUTDATED_TECHNOLOGY = "outdated_technology"
    ATTACK_SURFACE_CHANGE = "attack_surface_change"
    UNKNOWN_ASSET = "unknown_asset"


class FindingStatus(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    REMEDIATION_READY = "remediation_ready"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class FindingState(StrEnum):
    """Evidence maturity of a finding (see DetectionMethod docstring)."""

    DETECTED = "detected"
    POTENTIALLY_AFFECTED = "potentially_affected"
    NEEDS_VERIFICATION = "needs_verification"
    CONFIRMED = "confirmed"


class Exposure(StrEnum):
    INTERNAL = "internal"
    LIMITED = "limited"
    INTERNET_FACING = "internet_facing"


class ChangeType(StrEnum):
    NEW_ASSET = "new_asset"
    ASSET_REMOVED = "asset_removed"
    NEW_PORT = "new_port"
    PORT_CLOSED = "port_closed"
    NEW_SERVICE = "new_service"
    SERVICE_REMOVED = "service_removed"
    TECHNOLOGY_CHANGED = "technology_changed"
    VERSION_CHANGED = "version_changed"
    CERTIFICATE_CHANGED = "certificate_changed"
    RISK_INCREASED = "risk_increased"
    RISK_DECREASED = "risk_decreased"


class UserRole(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"

    @property
    def can_scan(self) -> bool:
        return self in {UserRole.OWNER, UserRole.ADMIN, UserRole.ANALYST}

    @property
    def can_manage(self) -> bool:
        return self in {UserRole.OWNER, UserRole.ADMIN}
