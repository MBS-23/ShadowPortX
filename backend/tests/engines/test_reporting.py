from shadowportx.db.base import session_scope
from shadowportx.engines.reporting import gather_report_data, render_csv_findings, render_html


async def test_reporting_renders(seeded):
    async with session_scope() as session:
        data = await gather_report_data(session, seeded["org_id"])
    assert "summary" in data and "findings" in data and "assets" in data
    csv = render_csv_findings(data)
    assert "SPX ID" in csv
    html = render_html(data)
    assert "ShadowPortX" in html and "Findings" in html
