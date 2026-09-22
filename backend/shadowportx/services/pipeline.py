"""Scan pipeline — the end-to-end DISCOVER → IDENTIFY → VERIFY → CORRELATE → PRIORITIZE
→ MONITOR flow, persisted to the database.

Given a queued :class:`Scan`, it enforces scope, runs recon + port/service discovery,
enriches web/TLS ports, performs non-destructive verification, correlates CVE intel,
builds SPX-scored findings, and records attack-surface changes vs the previous state.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx.core import enums, scope
from shadowportx.core.config import settings
from shadowportx.db import models
from shadowportx.db.base import utcnow
from shadowportx.engines import verification
from shadowportx.engines.correlation import finding as fb
from shadowportx.engines.correlation.finding import AssetCtx
from shadowportx.engines.intel import CVECorrelator
from shadowportx.engines.recon import ReconEngine, http_intel, tls_intel
from shadowportx.engines.results import ServiceInfo
from shadowportx.engines.scanner import ScanConfig, ScanOrchestrator
from shadowportx.engines.scanner.ports import resolve_ports
from shadowportx.services import persistence as P

ProgressHook = Callable[[float, str], Awaitable[None] | None]

_TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 993, 995, 8443, 9443, 4848, 8834}
_WEB_PORTS = {80, 81, 443, 591, 2082, 2480, 3000, 5000, 5601, 7474, 8000, 8008, 8080,
              8081, 8086, 8088, 8090, 8161, 8443, 8888, 9000, 9090, 9200, 9443, 9999,
              15672, 10000}


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


async def _load_scope(session: AsyncSession, org_id: int) -> list[scope.ScopeRuleData]:
    rows = (await session.execute(
        select(models.ScopeRule).where(models.ScopeRule.organization_id == org_id)
    )).scalars().all()
    return [scope.ScopeRuleData(kind=r.kind, target_type=r.target_type, value=r.value) for r in rows]


class ScanPipeline:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.recon = ReconEngine()
        self.correlator = CVECorrelator()

    async def run(self, scan: models.Scan, progress: ProgressHook | None = None) -> models.Scan:
        session = self.session
        org_id = scan.organization_id
        target = scan.target.strip().lower().rstrip(".")
        cfg = scan.config or {}

        async def report(pct: float, msg: str) -> None:
            scan.progress = round(pct, 1)
            scan.stats = {**(scan.stats or {}), "phase": msg}
            await session.commit()
            if progress:
                res = progress(pct, msg)
                if hasattr(res, "__await__"):
                    await res

        # --- 1. Scope enforcement ------------------------------------------------
        rules = await _load_scope(session, org_id)
        decision = scope.evaluate(target, rules, enforce=settings.enforce_scope)
        if not decision.allowed:
            scan.status = enums.ScanStatus.BLOCKED
            scan.error = decision.reason
            scan.finished_at = utcnow()
            await P.audit(session, org_id, "scan.blocked", target, reason=decision.reason)
            await session.commit()
            return scan

        scan.status = enums.ScanStatus.RUNNING
        scan.started_at = utcnow()
        await P.audit(session, org_id, "scan.started", target, scan_type=scan.scan_type.value)
        await report(3, "reconnaissance")

        # --- 2. Recon ------------------------------------------------------------
        is_ip = _is_ip(target)
        do_subs = bool(cfg.get("subdomains", True)) and not is_ip
        recon = await self.recon.run(target, do_subdomains=do_subs, do_whois=not is_ip)
        primary_ip = recon.resolved_ips[0] if recon.resolved_ips else (target if is_ip else None)
        exposure = P.exposure_for_ip(primary_ip)

        asset, asset_created = await P.upsert_asset(
            session, org_id, enums.AssetType.IP if is_ip else enums.AssetType.DOMAIN,
            target, ip_address=primary_ip, exposure=exposure,
        )
        asset.meta = {"dns": recon.dns_records, "whois": recon.whois,
                      "resolved_ips": recon.resolved_ips, "subdomains": recon.subdomains}
        prev_risk = asset.risk_score
        await session.flush()

        if asset_created:
            session.add(models.AssetChange(
                organization_id=org_id, asset_id=asset.id, scan_id=scan.id,
                change_type=enums.ChangeType.NEW_ASSET, summary=f"New asset discovered: {target}",
                detail={"ip": primary_ip}))

        # Record discovered subdomains as inventory assets.
        new_subdomains: list[str] = []
        for sub in recon.subdomains:
            _, created = await P.upsert_asset(session, org_id, enums.AssetType.SUBDOMAIN, sub, parent_id=asset.id)
            if created:
                new_subdomains.append(sub)
                session.add(models.AssetChange(
                    organization_id=org_id, scan_id=scan.id, change_type=enums.ChangeType.NEW_ASSET,
                    summary=f"New subdomain discovered: {sub}", detail={"parent": target}))
        await session.commit()

        # Snapshot prior open ports for change detection.
        prev_ports = {
            (p.number, p.protocol)
            for p in (await session.execute(select(models.Port).where(models.Port.asset_id == asset.id))).scalars().all()
            if p.state == enums.PortState.OPEN
        }

        # --- 3. Port & service discovery -----------------------------------------
        await report(10, "port & service discovery")
        ports = resolve_ports(cfg.get("ports", settings.scan_default_ports))
        technique = enums.ScanType(cfg.get("technique", enums.ScanType.TCP_CONNECT.value)) \
            if cfg.get("technique") else enums.ScanType.TCP_CONNECT
        scan_cfg = ScanConfig(
            ports=ports, technique=technique,
            concurrency=int(cfg.get("concurrency", settings.scan_max_concurrency)),
            rate_limit_per_sec=int(cfg.get("rate_limit", settings.scan_rate_limit_per_sec)),
        )
        orch = ScanOrchestrator(scan_cfg)

        async def scan_progress(done: int, total: int) -> None:
            await report(10 + (done / max(1, total)) * 55, f"scanning ports ({done}/{total})")

        open_ports = await orch.run(target, progress_cb=scan_progress)

        ctx = AssetCtx(value=target, exposure=asset.exposure, criticality=asset.criticality)
        drafts: list[fb.FindingDraft] = []
        service_key_to_id: dict[str, int] = {}
        curr_ports: set[tuple[int, enums.Protocol]] = set()
        services_count = 0

        await report(66, "enrichment, verification & correlation")
        for r in open_ports:
            curr_ports.add((r.port, r.protocol))
            port_row, port_created = await P.upsert_port(session, asset.id, r.port, r.protocol, r.state)
            if port_created and not asset_created:
                session.add(models.AssetChange(
                    organization_id=org_id, asset_id=asset.id, scan_id=scan.id,
                    change_type=enums.ChangeType.NEW_PORT,
                    summary=f"New open port {r.port}/{r.protocol.value} on {target}",
                    detail={"port": r.port, "protocol": r.protocol.value}))

            svc_info = r.service or ServiceInfo()
            if r.banner:
                svc_info.evidence = {**svc_info.evidence, "banner_excerpt": r.banner[:200]}
            svc_row = await P.upsert_service(session, port_row.id, svc_info)
            service_key_to_id[f"{r.port}/{r.protocol.value}"] = svc_row.id
            services_count += 1

            # Exposed-sensitive-service finding.
            if (d := fb.finding_for_exposed_service(ctx, r.port, r.protocol, r.service)):
                drafts.append(d)

            # Web enrichment (HTTP intel + missing-header findings).
            application = (r.service.evidence.get("application") if r.service else None)
            if r.protocol == enums.Protocol.TCP and (
                r.port in _WEB_PORTS or (r.service and r.service.name in ("http", "https"))
            ):
                scheme = "https" if (r.port in _TLS_PORTS or (r.service and r.service.name == "https")) else "http"
                http = await http_intel.probe(f"{scheme}://{target}:{r.port}")
                if http:
                    for tech in http.technologies:
                        await P.upsert_technology(session, asset.id, tech)
                    drafts.extend(fb.findings_for_http(ctx, r.port, http))

            # TLS enrichment.
            if r.protocol == enums.Protocol.TCP and r.port in _TLS_PORTS:
                cert = await tls_intel.analyze(target, r.port)
                if cert:
                    await P.upsert_certificate(session, asset.id, cert)
                    drafts.extend(fb.findings_for_tls(ctx, r.port, cert))

            # Non-destructive service verification.
            if r.service and (r.service.name in verification.supported_services() or application):
                vres = await verification.run_verification(
                    r.service.name, target, r.port, application=application)
                if vres:
                    svc_row.verified = True
                    if (vd := fb.finding_for_verification(ctx, r.port, r.protocol, vres)):
                        drafts.append(vd)

            # CVE correlation (version -> known-vulnerability intelligence).
            if r.service and (r.service.product or r.service.version):
                cves = self.correlator.correlate(r.service)
                if cves:
                    for cve in cves:
                        await P.upsert_vulnerability(session, cve)
                    drafts.extend(fb.findings_for_cves(ctx, r.port, r.protocol, r.service, cves))

            await session.flush()

        # --- 4. Persist findings --------------------------------------------------
        await report(88, "scoring & findings")
        vuln_ids: dict[str, int] = {}
        for v in (await session.execute(select(models.Vulnerability))).scalars().all():
            vuln_ids[v.cve_id] = v.id

        new_findings = 0
        max_risk = 0.0
        produced_fps: set[str] = set()
        alerts: list[dict] = []
        for d in drafts:
            svc_id = service_key_to_id.get(d.service_key) if d.service_key else None
            vuln_id = vuln_ids.get(d.cve_id) if d.cve_id else None
            finding, created = await P.upsert_finding(session, org_id, asset.id, d, svc_id, vuln_id)
            new_findings += int(created)
            max_risk = max(max_risk, d.risk_score)
            produced_fps.add(d.fingerprint)
            # Queue an alert for brand-new high/critical findings.
            if created and d.severity in (enums.Severity.HIGH, enums.Severity.CRITICAL):
                alerts.append({"spx_id": finding.spx_id, "title": d.title,
                               "severity": d.severity.value, "risk": d.risk_score, "asset": target})

        # Auto-resolve findings that were not reproduced this scan (remediation loop).
        resolved_findings = 0
        open_rows = (await session.execute(
            select(models.Finding).where(
                models.Finding.organization_id == org_id,
                models.Finding.asset_id == asset.id,
                models.Finding.status.notin_([
                    enums.FindingStatus.RESOLVED, enums.FindingStatus.FALSE_POSITIVE,
                    enums.FindingStatus.ACCEPTED_RISK,
                ]),
            )
        )).scalars().all()
        for row in open_rows:
            if row.fingerprint not in produced_fps:
                row.status = enums.FindingStatus.RESOLVED
                row.resolved_at = utcnow()
                resolved_findings += 1

        # --- 5. Change detection --------------------------------------------------
        closed = prev_ports - curr_ports
        for (num, proto) in closed:
            row = (await session.execute(select(models.Port).where(
                models.Port.asset_id == asset.id, models.Port.number == num, models.Port.protocol == proto
            ))).scalar_one_or_none()
            if row:
                row.state = enums.PortState.CLOSED
            session.add(models.AssetChange(
                organization_id=org_id, asset_id=asset.id, scan_id=scan.id,
                change_type=enums.ChangeType.PORT_CLOSED,
                summary=f"Port {num}/{proto.value} no longer open on {target}",
                detail={"port": num, "protocol": proto.value}))

        # Asset risk rollup + risk-trend change.
        asset.risk_score = round(max_risk, 1)
        asset.last_seen = utcnow()
        if not asset_created and asset.risk_score > prev_risk + 5:
            session.add(models.AssetChange(
                organization_id=org_id, asset_id=asset.id, scan_id=scan.id,
                change_type=enums.ChangeType.RISK_INCREASED,
                summary=f"Risk increased on {target}: {prev_risk:.0f} → {asset.risk_score:.0f}",
                detail={"from": prev_risk, "to": asset.risk_score}, risk_delta=asset.risk_score - prev_risk))
        elif not asset_created and asset.risk_score < prev_risk - 5:
            session.add(models.AssetChange(
                organization_id=org_id, asset_id=asset.id, scan_id=scan.id,
                change_type=enums.ChangeType.RISK_DECREASED,
                summary=f"Risk decreased on {target}: {prev_risk:.0f} → {asset.risk_score:.0f}",
                detail={"from": prev_risk, "to": asset.risk_score}, risk_delta=asset.risk_score - prev_risk))

        # --- 6. Finalize ----------------------------------------------------------
        scan.status = enums.ScanStatus.COMPLETED
        scan.finished_at = utcnow()
        scan.progress = 100.0
        scan.stats = {
            "phase": "completed",
            "open_ports": len(curr_ports),
            "services": services_count,
            "findings": len(drafts),
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "subdomains": len(recon.subdomains),
            "new_subdomains": len(new_subdomains),
            "new_ports": len(curr_ports - prev_ports),
            "closed_ports": len(closed),
            "asset_risk": asset.risk_score,
            "notes": scan_cfg.notes,
        }
        await P.audit(session, org_id, "scan.completed", target, **scan.stats)

        # Capture an org metrics snapshot for security-trend intelligence.
        from shadowportx.services import metrics as metrics_svc
        await metrics_svc.capture_snapshot(session, org_id, scan.id, scan.stats)

        await session.commit()

        # Fire outbound alerts for new high/critical findings (best-effort, post-commit).
        if alerts:
            try:
                from shadowportx.services import notifications
                await notifications.dispatch(org_id, alerts)
            except Exception:  # noqa: BLE001 - notifications must never fail a scan
                pass
        return scan
