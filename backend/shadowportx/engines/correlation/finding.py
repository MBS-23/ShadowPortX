"""Finding builders — pure functions that turn signals into scored :class:`FindingDraft`s.

Each builder attaches evidence, a recommendation, and an SPX Exposure Score computed from
the asset's business context. The pipeline persists the drafts and dedupes by fingerprint.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from shadowportx.core import enums
from shadowportx.engines.recon.http_intel import SECURITY_HEADERS
from shadowportx.engines.results import (
    CertInfo,
    CorrelatedVuln,
    HttpInfo,
    ServiceInfo,
    VerificationResult,
)
from shadowportx.engines.risk import compute_exposure_score


@dataclass
class AssetCtx:
    """Business context needed to score findings."""

    value: str
    exposure: enums.Exposure = enums.Exposure.INTERNET_FACING
    criticality: enums.Criticality = enums.Criticality.UNKNOWN


@dataclass
class FindingDraft:
    title: str
    category: enums.FindingCategory
    severity: enums.Severity
    confidence: enums.Confidence
    state: enums.FindingState
    detection_method: enums.DetectionMethod
    description: str
    recommendation: str
    fingerprint: str
    exposure: enums.Exposure = enums.Exposure.INTERNET_FACING
    evidence: dict = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_breakdown: dict = field(default_factory=dict)
    cve_id: str | None = None
    port: int | None = None
    service_key: str | None = None  # "port/protocol" to link to a persisted service


def _fp(*parts: object) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:32]


def _score(draft_severity, ctx, *, cvss=None, confidence, state, exploit_known=False, recently=False):
    return compute_exposure_score(
        severity=draft_severity,
        cvss_score=cvss,
        exposure=ctx.exposure,
        criticality=ctx.criticality,
        confidence=confidence,
        exploit_known=exploit_known,
        state=state,
        recently_exposed=recently,
    )


# Services that are a finding *merely by being internet-facing*.
SENSITIVE_SERVICES: dict[str, tuple[enums.Severity, str]] = {
    "redis": (enums.Severity.HIGH, "In-memory data store"),
    "memcached": (enums.Severity.HIGH, "In-memory cache (also a DDoS amplifier)"),
    "mongodb": (enums.Severity.HIGH, "NoSQL database"),
    "mysql": (enums.Severity.HIGH, "Relational database"),
    "postgresql": (enums.Severity.HIGH, "Relational database"),
    "ms-sql": (enums.Severity.HIGH, "Relational database"),
    "oracle": (enums.Severity.HIGH, "Relational database"),
    "elasticsearch": (enums.Severity.HIGH, "Search/analytics datastore"),
    "docker": (enums.Severity.CRITICAL, "Container control plane"),
    "kubernetes": (enums.Severity.CRITICAL, "Container orchestration API"),
    "etcd": (enums.Severity.CRITICAL, "Cluster key-value store"),
    "rdp": (enums.Severity.HIGH, "Remote desktop"),
    "ms-wbt-server": (enums.Severity.HIGH, "Remote desktop (RDP)"),
    "vnc": (enums.Severity.HIGH, "Remote desktop"),
    "telnet": (enums.Severity.HIGH, "Cleartext remote shell"),
    "ftp": (enums.Severity.MEDIUM, "File transfer (often cleartext)"),
    "smb": (enums.Severity.HIGH, "File sharing"),
    "microsoft-ds": (enums.Severity.HIGH, "SMB file sharing"),
    "ldap": (enums.Severity.MEDIUM, "Directory service"),
    "rabbitmq": (enums.Severity.MEDIUM, "Message broker"),
    "kafka": (enums.Severity.MEDIUM, "Event streaming"),
    "zookeeper": (enums.Severity.MEDIUM, "Coordination service"),
    "kibana": (enums.Severity.MEDIUM, "Analytics UI"),
    "grafana": (enums.Severity.MEDIUM, "Monitoring UI"),
    "jenkins": (enums.Severity.HIGH, "CI/CD server"),
}


def finding_for_exposed_service(
    ctx: AssetCtx, port: int, protocol: enums.Protocol, service: ServiceInfo | None
) -> FindingDraft | None:
    name = (service.name if service else None) or ""
    if name not in SENSITIVE_SERVICES:
        return None
    if ctx.exposure != enums.Exposure.INTERNET_FACING:
        # Internal exposure of these is lower priority (still recorded elsewhere).
        base_sev = enums.Severity.MEDIUM
    else:
        base_sev = SENSITIVE_SERVICES[name][0]
    desc_role = SENSITIVE_SERVICES[name][1]
    confidence = service.confidence if service else enums.Confidence.LOW
    sc = _score(base_sev, ctx, confidence=confidence, state=enums.FindingState.DETECTED)
    return FindingDraft(
        title=f"Exposed {desc_role.lower()} ({name}) on port {port}",
        category=enums.FindingCategory.EXPOSED_SERVICE,
        severity=base_sev,
        confidence=confidence,
        state=enums.FindingState.DETECTED,
        detection_method=(service.detection_method if service else enums.DetectionMethod.PORT_STATE),
        exposure=ctx.exposure,
        description=(
            f"{desc_role} '{name}' is reachable on {ctx.value}:{port}/{protocol.value}. "
            f"Sensitive services should not be directly exposed to untrusted networks."
        ),
        recommendation=(
            "Restrict access with a firewall/security group, require authentication, and place "
            "the service behind a VPN or private network segment."
        ),
        evidence={"port": port, "protocol": protocol.value,
                  "service": name, "product": service.product if service else None},
        risk_score=sc.score,
        risk_breakdown=sc.breakdown,
        port=port,
        service_key=f"{port}/{protocol.value}",
        fingerprint=_fp(ctx.value, "exposed_service", port, protocol.value, name),
    )


def findings_for_cves(
    ctx: AssetCtx, port: int, protocol: enums.Protocol, service: ServiceInfo, cves: list[CorrelatedVuln]
) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    product = service.product or service.name or "service"
    for cve in cves:
        sc = _score(
            cve.severity, ctx, cvss=cve.cvss_score, confidence=service.confidence,
            state=enums.FindingState.POTENTIALLY_AFFECTED, exploit_known=cve.exploit_known,
        )
        drafts.append(FindingDraft(
            title=f"{product} {service.version or ''} — {cve.cve_id}".strip(),
            category=enums.FindingCategory.VULNERABILITY_INTELLIGENCE,
            severity=cve.severity,
            confidence=service.confidence,
            state=enums.FindingState.POTENTIALLY_AFFECTED,
            detection_method=enums.DetectionMethod.CVE_CORRELATION,
            exposure=ctx.exposure,
            description=(
                f"The detected version of {product} ({service.version or 'unknown'}) matches public "
                f"vulnerability intelligence for {cve.cve_id}: {cve.description}. This is a "
                f"POTENTIAL match based on version correlation and requires verification."
            ),
            recommendation=(
                f"Confirm the running version, then upgrade to a fixed release. "
                f"Review vendor advisory for {cve.cve_id}."
            ),
            evidence={
                "cve": cve.cve_id, "cvss": cve.cvss_score, "cpe_match": cve.cpe_match,
                "exploit_known": cve.exploit_known, "detected_version": service.version,
                "detection": "version correlation (not exploitation)",
            },
            references=cve.references,
            risk_score=sc.score,
            risk_breakdown=sc.breakdown,
            cve_id=cve.cve_id,
            port=port,
            service_key=f"{port}/{protocol.value}",
            fingerprint=_fp(ctx.value, "cve", port, cve.cve_id),
        ))
    return drafts


def findings_for_http(ctx: AssetCtx, port: int, http: HttpInfo) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    missing = [h for h in SECURITY_HEADERS if not http.security_headers.get(h)]
    # Group critical headers into one finding to avoid noise; CSP/HSTS weighted higher.
    if missing:
        high_value = {"content-security-policy", "strict-transport-security"}
        sev = enums.Severity.MEDIUM if high_value & set(missing) else enums.Severity.LOW
        sc = _score(sev, ctx, confidence=enums.Confidence.HIGH, state=enums.FindingState.CONFIRMED)
        drafts.append(FindingDraft(
            title=f"Missing security headers on port {port} ({len(missing)})",
            category=enums.FindingCategory.MISSING_SECURITY_HEADER,
            severity=sev,
            confidence=enums.Confidence.HIGH,
            state=enums.FindingState.CONFIRMED,
            detection_method=enums.DetectionMethod.HTTP_HEADER,
            exposure=ctx.exposure,
            description=(
                f"The HTTP response from {http.final_url or ctx.value}:{port} is missing "
                f"{len(missing)} recommended security header(s): {', '.join(missing)}."
            ),
            recommendation=(
                "Add the missing headers. Prioritize Content-Security-Policy and "
                "Strict-Transport-Security, then X-Content-Type-Options and X-Frame-Options."
            ),
            evidence={"missing": missing, "present": [h for h in SECURITY_HEADERS if http.security_headers.get(h)],
                      "server": http.server, "status": http.status_code},
            risk_score=sc.score,
            risk_breakdown=sc.breakdown,
            port=port,
            fingerprint=_fp(ctx.value, "missing_headers", port),
        ))
    return drafts


def findings_for_tls(ctx: AssetCtx, port: int, cert: CertInfo) -> list[FindingDraft]:
    drafts: list[FindingDraft] = []
    weak = [v for v in cert.tls_versions if v in ("TLSv1.0", "TLSv1.1")]
    if weak:
        sc = _score(enums.Severity.MEDIUM, ctx, confidence=enums.Confidence.HIGH, state=enums.FindingState.CONFIRMED)
        drafts.append(FindingDraft(
            title=f"Weak TLS protocol versions enabled on port {port}",
            category=enums.FindingCategory.TLS_WEAKNESS,
            severity=enums.Severity.MEDIUM,
            confidence=enums.Confidence.HIGH,
            state=enums.FindingState.CONFIRMED,
            detection_method=enums.DetectionMethod.TLS_CERTIFICATE,
            exposure=ctx.exposure,
            description=f"The endpoint negotiates deprecated TLS versions: {', '.join(weak)}.",
            recommendation="Disable TLS 1.0/1.1; require TLS 1.2+ (prefer TLS 1.3).",
            evidence={"weak_versions": weak, "all_versions": cert.tls_versions},
            risk_score=sc.score, risk_breakdown=sc.breakdown, port=port,
            fingerprint=_fp(ctx.value, "weak_tls", port),
        ))
    if cert.days_until_expiry is not None and cert.days_until_expiry < 0:
        sev = enums.Severity.HIGH
        sc = _score(sev, ctx, confidence=enums.Confidence.HIGH, state=enums.FindingState.CONFIRMED)
        drafts.append(FindingDraft(
            title=f"Expired TLS certificate on port {port}",
            category=enums.FindingCategory.TLS_WEAKNESS,
            severity=sev, confidence=enums.Confidence.HIGH, state=enums.FindingState.CONFIRMED,
            detection_method=enums.DetectionMethod.TLS_CERTIFICATE, exposure=ctx.exposure,
            description=f"The certificate expired {abs(cert.days_until_expiry)} day(s) ago (notAfter {cert.not_after}).",
            recommendation="Renew and deploy a valid certificate; automate renewal (e.g. ACME).",
            evidence={"not_after": cert.not_after, "days_overdue": abs(cert.days_until_expiry)},
            risk_score=sc.score, risk_breakdown=sc.breakdown, port=port,
            fingerprint=_fp(ctx.value, "cert_expired", port),
        ))
    elif cert.days_until_expiry is not None and cert.days_until_expiry < 21:
        sc = _score(enums.Severity.LOW, ctx, confidence=enums.Confidence.HIGH, state=enums.FindingState.CONFIRMED)
        drafts.append(FindingDraft(
            title=f"TLS certificate expiring soon on port {port}",
            category=enums.FindingCategory.TLS_WEAKNESS,
            severity=enums.Severity.LOW, confidence=enums.Confidence.HIGH, state=enums.FindingState.CONFIRMED,
            detection_method=enums.DetectionMethod.TLS_CERTIFICATE, exposure=ctx.exposure,
            description=f"The certificate expires in {cert.days_until_expiry} day(s).",
            recommendation="Renew the certificate before expiry; automate renewal.",
            evidence={"not_after": cert.not_after, "days_until_expiry": cert.days_until_expiry},
            risk_score=sc.score, risk_breakdown=sc.breakdown, port=port,
            fingerprint=_fp(ctx.value, "cert_expiring", port),
        ))
    return drafts


def finding_for_verification(
    ctx: AssetCtx, port: int, protocol: enums.Protocol, vres: VerificationResult
) -> FindingDraft | None:
    if not vres.verified or vres.severity == enums.Severity.INFO:
        return None
    sc = _score(vres.severity, ctx, confidence=vres.confidence, state=enums.FindingState.CONFIRMED)
    return FindingDraft(
        title=f"{vres.service} — {vres.condition} on port {port}",
        category=enums.FindingCategory.SERVICE_MISCONFIGURATION,
        severity=vres.severity,
        confidence=vres.confidence,
        state=enums.FindingState.CONFIRMED,  # a condition was actually observed
        detection_method=enums.DetectionMethod.SERVICE_VERIFICATION,
        exposure=ctx.exposure,
        description=(
            f"Service verification confirmed a security condition on {ctx.value}:{port}: "
            f"{vres.condition}. {vres.evidence.get('observed', '')}"
        ),
        recommendation=vres.recommendation or "Review and harden the service configuration.",
        evidence=vres.evidence,
        risk_score=sc.score,
        risk_breakdown=sc.breakdown,
        port=port,
        service_key=f"{port}/{protocol.value}",
        fingerprint=_fp(ctx.value, "verification", port, vres.service, vres.condition),
    )
