"""ORM data model for ShadowPortX 2.0.

Mirrors the brief's security data model:

    Organization
      ├── Users
      ├── ScopeRules
      ├── Assets ── Ports ── Services
      │      ├── Technologies
      │      └── Certificates
      ├── Scans ── AssetChanges
      ├── Findings ── (Vulnerability catalog)
      ├── Reports
      └── AuditLog

Enums are stored as portable VARCHARs (``native_enum=False``) using their string
*values*, so the same schema works on SQLite and PostgreSQL.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from shadowportx.core import enums
from shadowportx.db.base import Base, utcnow


def enum_col(enum_cls: type, **kw: Any):
    """SAEnum that persists a StrEnum's *value* (not its name), portable across DBs."""
    return SAEnum(
        enum_cls,
        native_enum=False,
        validate_strings=True,
        values_callable=lambda e: [m.value for m in e],
        **kw,
    )


# --- Tenancy & identity -------------------------------------------------------
class Organization(Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text, default=None)

    users: Mapped[list[User]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    scope_rules: Mapped[list[ScopeRule]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    assets: Mapped[list[Asset]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    scans: Mapped[list[Scan]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("organization_id", "email", name="uq_user_org_email"),)

    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(255), index=True)
    full_name: Mapped[str | None] = mapped_column(String(200), default=None)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[enums.UserRole] = mapped_column(enum_col(enums.UserRole), default=enums.UserRole.VIEWER)
    is_active: Mapped[bool] = mapped_column(default=True)

    organization: Mapped[Organization] = relationship(back_populates="users")


class ScopeRule(Base):
    """Authorization guardrail. A target is scannable only if it matches an allow
    rule and no deny rule (deny wins). See core/scope.py for evaluation logic."""

    __tablename__ = "scope_rules"

    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(8))          # "allow" | "deny"
    target_type: Mapped[str] = mapped_column(String(16))  # "domain" | "wildcard" | "ip" | "cidr"
    value: Mapped[str] = mapped_column(String(255))
    note: Mapped[str | None] = mapped_column(String(255), default=None)

    organization: Mapped[Organization] = relationship(back_populates="scope_rules")


# --- Asset inventory ----------------------------------------------------------
class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("organization_id", "type", "value", name="uq_asset_identity"),
        Index("ix_asset_org_risk", "organization_id", "risk_score"),
    )

    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    type: Mapped[enums.AssetType] = mapped_column(enum_col(enums.AssetType), index=True)
    value: Mapped[str] = mapped_column(String(255), index=True)   # domain / ip / url
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), default=None)

    status: Mapped[enums.AssetStatus] = mapped_column(enum_col(enums.AssetStatus), default=enums.AssetStatus.UNKNOWN)
    exposure: Mapped[enums.Exposure] = mapped_column(enum_col(enums.Exposure), default=enums.Exposure.INTERNET_FACING)

    # Business context (drives risk contextualization)
    criticality: Mapped[enums.Criticality] = mapped_column(enum_col(enums.Criticality), default=enums.Criticality.UNKNOWN)
    environment: Mapped[enums.Environment] = mapped_column(enum_col(enums.Environment), default=enums.Environment.UNKNOWN)
    owner: Mapped[str | None] = mapped_column(String(200), default=None)
    business_unit: Mapped[str | None] = mapped_column(String(200), default=None)
    application: Mapped[str | None] = mapped_column(String(200), default=None)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)

    # Discovery / enrichment
    ip_address: Mapped[str | None] = mapped_column(String(64), default=None)
    asn: Mapped[str | None] = mapped_column(String(64), default=None)
    hosting: Mapped[str | None] = mapped_column(String(120), default=None)
    is_known: Mapped[bool] = mapped_column(default=True)  # False => shadow/unknown asset

    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)  # dns/whois/http/asn context
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)

    organization: Mapped[Organization] = relationship(back_populates="assets")
    ports: Mapped[list[Port]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    technologies: Mapped[list[Technology]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    certificates: Mapped[list[Certificate]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[list[Finding]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    changes: Mapped[list[AssetChange]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"
    __table_args__ = (UniqueConstraint("asset_id", "number", "protocol", name="uq_port_identity"),)

    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    number: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[enums.Protocol] = mapped_column(enum_col(enums.Protocol), default=enums.Protocol.TCP)
    state: Mapped[enums.PortState] = mapped_column(enum_col(enums.PortState), default=enums.PortState.OPEN)
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="ports")
    services: Mapped[list[Service]] = relationship(back_populates="port", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"

    port_id: Mapped[int] = mapped_column(ForeignKey("ports.id", ondelete="CASCADE"), index=True)
    name: Mapped[str | None] = mapped_column(String(80), default=None)      # e.g. "http", "ssh", "redis"
    product: Mapped[str | None] = mapped_column(String(120), default=None)  # e.g. "nginx", "OpenSSH"
    version: Mapped[str | None] = mapped_column(String(80), default=None)
    cpe: Mapped[str | None] = mapped_column(String(255), default=None)
    banner: Mapped[str | None] = mapped_column(Text, default=None)
    confidence: Mapped[enums.Confidence] = mapped_column(enum_col(enums.Confidence), default=enums.Confidence.MEDIUM)
    detection_method: Mapped[enums.DetectionMethod] = mapped_column(
        enum_col(enums.DetectionMethod), default=enums.DetectionMethod.PORT_STATE
    )
    verified: Mapped[bool] = mapped_column(default=False)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)

    port: Mapped[Port] = relationship(back_populates="services")


class Technology(Base):
    __tablename__ = "technologies"

    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120), index=True)
    category: Mapped[str | None] = mapped_column(String(80), default=None)  # web-server, framework, cms...
    version: Mapped[str | None] = mapped_column(String(80), default=None)
    cpe: Mapped[str | None] = mapped_column(String(255), default=None)
    confidence: Mapped[enums.Confidence] = mapped_column(enum_col(enums.Confidence), default=enums.Confidence.MEDIUM)
    evidence: Mapped[list] = mapped_column(JSON, default=list)  # list of evidence strings
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="technologies")


class Certificate(Base):
    __tablename__ = "certificates"

    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    subject: Mapped[str | None] = mapped_column(String(255), default=None)
    issuer: Mapped[str | None] = mapped_column(String(255), default=None)
    serial: Mapped[str | None] = mapped_column(String(120), default=None)
    not_before: Mapped[datetime | None] = mapped_column(default=None)
    not_after: Mapped[datetime | None] = mapped_column(default=None)
    sans: Mapped[list[str]] = mapped_column(JSON, default=list)
    signature_algorithm: Mapped[str | None] = mapped_column(String(80), default=None)
    key_bits: Mapped[int | None] = mapped_column(Integer, default=None)
    tls_versions: Mapped[list[str]] = mapped_column(JSON, default=list)
    is_valid: Mapped[bool] = mapped_column(default=True)
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(95), default=None)
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)

    asset: Mapped[Asset] = relationship(back_populates="certificates")


# --- Scans & change tracking --------------------------------------------------
class Scan(Base):
    __tablename__ = "scans"

    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    scan_type: Mapped[enums.ScanType] = mapped_column(enum_col(enums.ScanType), default=enums.ScanType.FULL)
    status: Mapped[enums.ScanStatus] = mapped_column(enum_col(enums.ScanStatus), default=enums.ScanStatus.QUEUED)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)   # counts: assets/services/findings...
    error: Mapped[str | None] = mapped_column(Text, default=None)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)

    organization: Mapped[Organization] = relationship(back_populates="scans")
    changes: Mapped[list[AssetChange]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class AssetChange(Base):
    __tablename__ = "asset_changes"

    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), default=None, index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), default=None)
    change_type: Mapped[enums.ChangeType] = mapped_column(enum_col(enums.ChangeType), index=True)
    summary: Mapped[str] = mapped_column(String(500))
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    risk_delta: Mapped[float] = mapped_column(Float, default=0.0)
    detected_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)

    asset: Mapped[Asset | None] = relationship(back_populates="changes")
    scan: Mapped[Scan | None] = relationship(back_populates="changes")


# --- Vulnerability intelligence & findings ------------------------------------
class Vulnerability(Base):
    """CVE catalog entry (seed dataset + optional NVD enrichment)."""

    __tablename__ = "vulnerabilities"

    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str | None] = mapped_column(String(255), default=None)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    cvss_score: Mapped[float | None] = mapped_column(Float, default=None)
    cvss_vector: Mapped[str | None] = mapped_column(String(120), default=None)
    severity: Mapped[enums.Severity] = mapped_column(enum_col(enums.Severity), default=enums.Severity.INFO)
    cpes: Mapped[list[str]] = mapped_column(JSON, default=list)
    cwe: Mapped[str | None] = mapped_column(String(32), default=None)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)
    exploit_known: Mapped[bool] = mapped_column(default=False)  # KEV / public exploit intel
    published: Mapped[str | None] = mapped_column(String(40), default=None)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_finding_org_status", "organization_id", "status"),)

    spx_id: Mapped[str] = mapped_column(String(24), unique=True, index=True)  # e.g. SPX-2026-00041
    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"), default=None)
    vulnerability_id: Mapped[int | None] = mapped_column(ForeignKey("vulnerabilities.id", ondelete="SET NULL"), default=None)

    title: Mapped[str] = mapped_column(String(255))
    category: Mapped[enums.FindingCategory] = mapped_column(enum_col(enums.FindingCategory), index=True)
    severity: Mapped[enums.Severity] = mapped_column(enum_col(enums.Severity), index=True)
    confidence: Mapped[enums.Confidence] = mapped_column(enum_col(enums.Confidence), default=enums.Confidence.MEDIUM)
    state: Mapped[enums.FindingState] = mapped_column(enum_col(enums.FindingState), default=enums.FindingState.DETECTED)
    status: Mapped[enums.FindingStatus] = mapped_column(enum_col(enums.FindingStatus), default=enums.FindingStatus.NEW)
    exposure: Mapped[enums.Exposure] = mapped_column(enum_col(enums.Exposure), default=enums.Exposure.INTERNET_FACING)
    detection_method: Mapped[enums.DetectionMethod] = mapped_column(
        enum_col(enums.DetectionMethod), default=enums.DetectionMethod.PORT_STATE
    )

    description: Mapped[str | None] = mapped_column(Text, default=None)
    recommendation: Mapped[str | None] = mapped_column(Text, default=None)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    references: Mapped[list[str]] = mapped_column(JSON, default=list)

    # SPX Exposure Score + transparent breakdown of the contributing factors.
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    risk_breakdown: Mapped[dict] = mapped_column(JSON, default=dict)

    # Remediation workflow
    assignee: Mapped[str | None] = mapped_column(String(200), default=None)
    team: Mapped[str | None] = mapped_column(String(200), default=None)
    due_date: Mapped[datetime | None] = mapped_column(default=None)

    first_seen: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(default=None)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)  # dedupe key across scans

    organization: Mapped[Organization] = relationship(back_populates="findings")
    asset: Mapped[Asset] = relationship(back_populates="findings")
    vulnerability: Mapped[Vulnerability | None] = relationship()


class Report(Base):
    __tablename__ = "reports"

    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))     # "executive" | "technical"
    fmt: Mapped[str] = mapped_column(String(8))        # "pdf" | "csv" | "json" | "html"
    path: Mapped[str] = mapped_column(String(500))
    summary: Mapped[dict] = mapped_column(JSON, default=dict)


class AuditLog(Base):
    __tablename__ = "audit_log"

    organization_id: Mapped[int | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), default=None, index=True)
    actor: Mapped[str] = mapped_column(String(200), default="system")
    action: Mapped[str] = mapped_column(String(120), index=True)
    target: Mapped[str | None] = mapped_column(String(255), default=None)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ts: Mapped[datetime] = mapped_column(default=utcnow, index=True)


class Schedule(Base):
    """Recurring scan schedule — powers continuous attack-surface monitoring."""

    __tablename__ = "schedules"

    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    target: Mapped[str] = mapped_column(String(255))
    interval_minutes: Mapped[int] = mapped_column(Integer, default=1440)
    ports: Mapped[str | None] = mapped_column(String(120), default=None)
    subdomains: Mapped[bool] = mapped_column(default=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(default=None)
    next_run_at: Mapped[datetime | None] = mapped_column(default=None, index=True)


class NotificationChannel(Base):
    """Outbound alert channel. ``kind`` = 'slack' (Slack/Teams/Discord-compatible incoming
    webhook payload) or 'generic' (raw JSON POST). Alerts fire on new findings at or above
    ``min_severity``. This is the extension point enterprise connectors (Jira/SIEM) plug into.
    """

    __tablename__ = "notification_channels"

    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(16), default="slack")
    url: Mapped[str] = mapped_column(String(500))
    min_severity: Mapped[enums.Severity] = mapped_column(enum_col(enums.Severity), default=enums.Severity.HIGH)
    enabled: Mapped[bool] = mapped_column(default=True)


class MetricSnapshot(Base):
    """Point-in-time org security metrics — the basis for security trends & posture deltas.

    Captured at each scan completion. ``metrics`` is a flexible JSON bag so new metrics can
    be tracked without a migration.
    """

    __tablename__ = "metric_snapshots"
    __table_args__ = (Index("ix_snapshot_org_ts", "organization_id", "ts"),)

    organization_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), default=None)
    ts: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    org_risk: Mapped[float] = mapped_column(Float, default=0.0)
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)

