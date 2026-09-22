"""Report data gathering and renderers (JSON/CSV/HTML/PDF)."""

from __future__ import annotations

import csv
import io

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx.core import enums
from shadowportx.db import models
from shadowportx.db.base import utcnow


async def gather_report_data(session: AsyncSession, org_id: int) -> dict:
    org = (await session.execute(
        select(models.Organization).where(models.Organization.id == org_id)
    )).scalar_one_or_none()

    assets = (await session.execute(
        select(models.Asset).where(models.Asset.organization_id == org_id)
        .order_by(desc(models.Asset.risk_score))
    )).scalars().all()

    findings = (await session.execute(
        select(models.Finding).where(
            models.Finding.organization_id == org_id,
            models.Finding.status != enums.FindingStatus.RESOLVED,
        ).order_by(desc(models.Finding.risk_score))
    )).scalars().all()

    changes = (await session.execute(
        select(models.AssetChange).where(models.AssetChange.organization_id == org_id)
        .order_by(desc(models.AssetChange.detected_at)).limit(25)
    )).scalars().all()

    sev_counts: dict[str, int] = {s.value: 0 for s in enums.Severity}
    for f in findings:
        sev_counts[f.severity.value] += 1

    avg_risk = (await session.execute(
        select(func.avg(models.Asset.risk_score)).where(
            models.Asset.organization_id == org_id, models.Asset.risk_score > 0)
    )).scalar_one_or_none() or 0.0

    return {
        "generated_at": utcnow().isoformat(),
        "organization": org.name if org else "Unknown",
        "summary": {
            "org_risk": round(float(avg_risk), 1),
            "assets": len(assets),
            "open_findings": len(findings),
            "severity": sev_counts,
        },
        "assets": [
            {"value": a.value, "type": a.type.value, "ip": a.ip_address,
             "exposure": a.exposure.value, "criticality": a.criticality.value,
             "risk_score": a.risk_score}
            for a in assets
        ],
        "findings": [
            {"spx_id": f.spx_id, "title": f.title, "category": f.category.value,
             "severity": f.severity.value, "state": f.state.value, "status": f.status.value,
             "exposure": f.exposure.value, "risk_score": f.risk_score,
             "detection_method": f.detection_method.value, "recommendation": f.recommendation,
             "references": f.references, "evidence": f.evidence}
            for f in findings
        ],
        "changes": [
            {"type": c.change_type.value, "summary": c.summary,
             "detected_at": c.detected_at.isoformat()}
            for c in changes
        ],
    }


def render_csv_findings(data: dict) -> str:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["SPX ID", "Title", "Category", "Severity", "State", "Status",
                     "Exposure", "SPX Exposure Score", "Detection Method", "Recommendation"])
    for f in data["findings"]:
        writer.writerow([f["spx_id"], f["title"], f["category"], f["severity"], f["state"],
                         f["status"], f["exposure"], f["risk_score"], f["detection_method"],
                         (f["recommendation"] or "").replace("\n", " ")])
    return out.getvalue()


def render_html(data: dict) -> str:
    from jinja2 import Template

    template = Template(_HTML_TEMPLATE)
    return template.render(**data)


def render_pdf(data: dict, path: str) -> str:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    doc = SimpleDocTemplate(path, pagesize=A4, title="ShadowPortX Security Assessment")
    styles = getSampleStyleSheet()
    story = [
        Paragraph("ShadowPortX 2.0 — Security Assessment Report", styles["Title"]),
        Paragraph(f"Organization: {data['organization']}", styles["Normal"]),
        Paragraph(f"Generated: {data['generated_at']}", styles["Normal"]),
        Spacer(1, 16),
        Paragraph("Executive Summary", styles["Heading2"]),
    ]
    s = data["summary"]
    summary_tbl = Table([
        ["Organization Risk (avg SPX-ES)", str(s["org_risk"])],
        ["Assets", str(s["assets"])],
        ["Open Findings", str(s["open_findings"])],
        ["Critical / High", f"{s['severity']['critical']} / {s['severity']['high']}"],
        ["Medium / Low", f"{s['severity']['medium']} / {s['severity']['low']}"],
    ], colWidths=[240, 200])
    summary_tbl.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#0b1220")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story += [summary_tbl, Spacer(1, 16), Paragraph("Top Findings", styles["Heading2"])]

    rows = [["SPX ID", "Severity", "Score", "Title"]]
    for f in data["findings"][:25]:
        rows.append([f["spx_id"], f["severity"].upper(), str(f["risk_score"]), f["title"][:70]])
    tbl = Table(rows, colWidths=[95, 65, 45, 250])
    tbl.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b1220")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
    ]))
    story.append(tbl)
    doc.build(story)
    return path


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>ShadowPortX Report — {{ organization }}</title>
<style>
 body{font-family:system-ui,Segoe UI,sans-serif;margin:0;background:#0b1220;color:#e5e7eb;padding:32px}
 h1{font-size:24px;margin:0 0 4px} .muted{color:#94a3b8;font-size:13px}
 .cards{display:flex;gap:16px;flex-wrap:wrap;margin:24px 0}
 .card{background:#111a2e;border:1px solid #1f2b45;border-radius:12px;padding:16px 20px;min-width:150px}
 .card b{font-size:28px;display:block}
 table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #1f2b45}
 th{color:#94a3b8;font-weight:600}
 .sev-critical{color:#f87171;font-weight:700}.sev-high{color:#fb923c;font-weight:700}
 .sev-medium{color:#fbbf24}.sev-low{color:#60a5fa}.sev-info{color:#94a3b8}
</style></head><body>
 <h1>ShadowPortX 2.0 — Security Assessment</h1>
 <div class="muted">{{ organization }} · generated {{ generated_at }}</div>
 <div class="cards">
   <div class="card"><span class="muted">Org Risk</span><b>{{ summary.org_risk }}</b></div>
   <div class="card"><span class="muted">Assets</span><b>{{ summary.assets }}</b></div>
   <div class="card"><span class="muted">Open Findings</span><b>{{ summary.open_findings }}</b></div>
   <div class="card"><span class="muted">Critical</span><b class="sev-critical">{{ summary.severity.critical }}</b></div>
   <div class="card"><span class="muted">High</span><b class="sev-high">{{ summary.severity.high }}</b></div>
 </div>
 <h2>Findings</h2>
 <table><thead><tr><th>SPX ID</th><th>Severity</th><th>Score</th><th>Title</th><th>Recommendation</th></tr></thead>
 <tbody>
 {% for f in findings %}<tr>
   <td>{{ f.spx_id }}</td><td class="sev-{{ f.severity }}">{{ f.severity|upper }}</td>
   <td>{{ f.risk_score }}</td><td>{{ f.title }}</td><td class="muted">{{ f.recommendation }}</td>
 </tr>{% endfor %}
 </tbody></table>
</body></html>"""
