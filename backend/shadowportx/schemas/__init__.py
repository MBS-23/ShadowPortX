"""Pydantic request/response schemas for the API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from shadowportx.core import enums


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- auth ---
class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    """Self-service account creation. Password policy is enforced here so the same rule
    applies to every entry point (UI, API, scripts)."""

    email: str
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=120)

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        v = v.strip().lower()
        # Lightweight structural check — avoids pulling in the email-validator dependency
        # while rejecting obviously-malformed input before it reaches the database.
        local, _, domain = v.partition("@")
        if not local or "." not in domain or len(v) < 6:
            raise ValueError("Enter a valid email address")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: enums.UserRole
    email: str
    org_id: int


# --- scope ---
class ScopeRuleIn(BaseModel):
    kind: str = Field(pattern="^(allow|deny)$")
    target_type: str = Field(pattern="^(domain|wildcard|ip|cidr)$")
    value: str
    note: str | None = None


class ScopeRuleOut(ORMModel):
    id: int
    kind: str
    target_type: str
    value: str
    note: str | None = None


# --- scans ---
class ScanCreate(BaseModel):
    target: str
    scan_type: enums.ScanType = enums.ScanType.FULL
    ports: str | None = None            # "top100" | "top1000" | "1-1024" | "80,443"
    technique: enums.ScanType | None = None  # TCP_CONNECT | TCP_SYN | UDP
    subdomains: bool = True
    concurrency: int | None = None
    rate_limit: int | None = None
    engagement_id: int | None = None


class ScanOut(ORMModel):
    id: int
    target: str
    scan_type: enums.ScanType
    status: enums.ScanStatus
    progress: float
    stats: dict
    error: str | None = None
    engagement_id: int | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime


# --- services / ports / tech / certs ---
class ServiceOut(ORMModel):
    id: int
    name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    banner: str | None = None
    confidence: enums.Confidence
    detection_method: enums.DetectionMethod
    verified: bool
    evidence: dict


class PortOut(ORMModel):
    id: int
    number: int
    protocol: enums.Protocol
    state: enums.PortState
    first_seen: datetime
    last_seen: datetime
    services: list[ServiceOut] = []


class TechnologyOut(ORMModel):
    id: int
    name: str
    category: str | None = None
    version: str | None = None
    confidence: enums.Confidence
    evidence: list = []


class CertificateOut(ORMModel):
    id: int
    subject: str | None = None
    issuer: str | None = None
    not_after: datetime | None = None
    sans: list = []
    tls_versions: list = []
    is_valid: bool


# --- assets ---
class AssetOut(ORMModel):
    id: int
    type: enums.AssetType
    value: str
    status: enums.AssetStatus
    exposure: enums.Exposure
    criticality: enums.Criticality
    environment: enums.Environment
    ip_address: str | None = None
    is_known: bool
    risk_score: float
    first_seen: datetime
    last_seen: datetime


class AssetDetail(AssetOut):
    owner: str | None = None
    business_unit: str | None = None
    application: str | None = None
    tags: list = []
    meta: dict = {}
    ports: list[PortOut] = []
    technologies: list[TechnologyOut] = []
    certificates: list[CertificateOut] = []


class AssetUpdate(BaseModel):
    criticality: enums.Criticality | None = None
    environment: enums.Environment | None = None
    owner: str | None = None
    business_unit: str | None = None
    application: str | None = None
    tags: list[str] | None = None


# --- findings ---
class FindingOut(ORMModel):
    id: int
    spx_id: str
    asset_id: int
    title: str
    category: enums.FindingCategory
    severity: enums.Severity
    confidence: enums.Confidence
    state: enums.FindingState
    status: enums.FindingStatus
    exposure: enums.Exposure
    detection_method: enums.DetectionMethod
    risk_score: float
    first_seen: datetime
    last_seen: datetime


class FindingDetail(FindingOut):
    description: str | None = None
    recommendation: str | None = None
    evidence: dict = {}
    references: list = []
    risk_breakdown: dict = {}
    assignee: str | None = None
    team: str | None = None
    notes: str | None = None
    resolved_at: datetime | None = None
    validated_at: datetime | None = None


class FindingUpdate(BaseModel):
    status: enums.FindingStatus | None = None
    assignee: str | None = None
    team: str | None = None
    notes: str | None = None


class ValidationResult(BaseModel):
    finding_id: int
    spx_id: str
    validated: bool
    state: enums.FindingState
    condition: str | None = None
    severity: enums.Severity
    confidence: enums.Confidence
    evidence: dict = {}
    message: str


# --- changes ---
class ChangeOut(ORMModel):
    id: int
    asset_id: int | None = None
    change_type: enums.ChangeType
    summary: str
    detail: dict
    risk_delta: float
    detected_at: datetime


# --- dashboard ---
class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class Overview(BaseModel):
    org_risk: float
    assets: int
    internet_facing: int
    unknown_assets: int
    services: int
    technologies: int
    findings: int
    open_findings: int
    resolved_findings: int
    severity: SeverityCounts
    recent_changes: int
    scans: int
    top_findings: list[FindingOut] = []
    recent_changes_list: list[ChangeOut] = []


# --- inventory (services / technologies / vulnerabilities) ---
class ServiceRow(BaseModel):
    id: int
    asset_id: int
    asset: str
    port: int
    protocol: str
    name: str | None = None
    product: str | None = None
    version: str | None = None
    confidence: str
    verified: bool
    detection_method: str


class TechnologyRow(BaseModel):
    name: str
    category: str | None = None
    versions: list[str] = []
    asset_count: int


class VulnerabilityRow(BaseModel):
    id: int
    cve_id: str
    title: str | None = None
    cvss_score: float | None = None
    severity: enums.Severity
    exploit_known: bool
    affected_findings: int
    references: list[str] = []


# --- risk ---
class RiskAsset(BaseModel):
    id: int
    value: str
    risk_score: float
    exposure: str
    criticality: str


class RiskSummary(BaseModel):
    org_risk: float
    severity: SeverityCounts
    by_category: dict[str, int]
    by_exposure: dict[str, int]
    top_assets: list[RiskAsset] = []
    trend: list[dict] = []  # [{date, open_findings, avg_risk}]


# --- scan diff ---
class ScanDiff(BaseModel):
    scan_a: int
    scan_b: int
    target: str
    delta: dict          # {assets, services, findings, open_ports, ...}
    a_stats: dict
    b_stats: dict


# --- schedules (continuous monitoring) ---
class ScheduleIn(BaseModel):
    target: str
    interval_minutes: int = Field(ge=5, le=100000, default=1440)
    ports: str | None = None
    subdomains: bool = True
    enabled: bool = True


class ScheduleOut(ORMModel):
    id: int
    target: str
    interval_minutes: int
    ports: str | None = None
    subdomains: bool
    enabled: bool
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime


# --- notifications ---
class NotificationChannelIn(BaseModel):
    name: str
    kind: str = Field(default="slack", pattern="^(slack|generic)$")
    url: str
    min_severity: enums.Severity = enums.Severity.HIGH
    enabled: bool = True


class NotificationChannelOut(ORMModel):
    id: int
    name: str
    kind: str
    url: str
    min_severity: enums.Severity
    enabled: bool


# --- graph (asset relationship graph + blast radius) ---
class GraphNode(BaseModel):
    id: str
    type: str          # asset | ip | port | service | technology | vulnerability | finding
    label: str
    ref: dict = {}     # navigation + severity/risk metadata


class GraphEdge(BaseModel):
    source: str
    target: str
    rel: str           # RESOLVES_TO | EXPOSES | RUNS | USES | AFFECTED_BY | HAS_FINDING


class GraphResponse(BaseModel):
    asset_id: int
    root: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class BlastAsset(BaseModel):
    id: int
    value: str
    exposure: str
    criticality: str
    risk_score: float


class BlastRadius(BaseModel):
    key: str
    kind: str          # technology | cve
    affected: int
    internet_facing: int
    production: int
    critical_assets: int
    assets: list[BlastAsset] = []


# --- trends ---
class TrendPoint(BaseModel):
    ts: str
    org_risk: float
    metrics: dict


class Trends(BaseModel):
    series: list[TrendPoint] = []
    current: dict = {}
    previous: dict = {}
    change: dict = {}
    contributors: dict = {}
    executive: dict = {}


# --- engagements (3.0 workspace) ---
class EngagementIn(BaseModel):
    name: str
    client: str | None = None
    kind: str = Field(default="pentest", pattern="^(pentest|bug_bounty|internal)$")
    scope_note: str | None = None
    tester: str | None = None
    status: str = Field(default="active", pattern="^(planned|active|completed)$")
    notes: str | None = None


class EngagementOut(ORMModel):
    id: int
    name: str
    client: str | None = None
    kind: str
    status: str
    scope_note: str | None = None
    tester: str | None = None
    notes: str | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None
    created_at: datetime


class EngagementDetail(EngagementOut):
    stats: dict = {}
    scans: list[ScanOut] = []
    findings: list[FindingOut] = []


# --- admin console (owner/admin only) ---
class AdminUser(ORMModel):
    id: int
    email: str
    full_name: str | None = None
    role: enums.UserRole
    is_active: bool
    created_at: datetime
    last_active_at: datetime | None = None  # derived from the audit log


class AdminUserUpdate(BaseModel):
    role: enums.UserRole | None = None
    is_active: bool | None = None


class AdminActivity(BaseModel):
    actor: str
    action: str
    target: str | None = None
    ts: datetime


class AdminOverview(BaseModel):
    users_total: int
    users_active: int
    users_by_role: dict[str, int]
    new_users_7d: int
    logins_7d: int
    scans_total: int
    scans_active: int
    findings_total: int
    open_findings: int
    assets_total: int
    recent_signups: list[AdminUser] = []
    recent_activity: list[AdminActivity] = []
