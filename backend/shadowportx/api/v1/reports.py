"""Report generation endpoints (JSON / CSV / HTML / PDF)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from shadowportx.api.deps import Context, get_context
from shadowportx.core.config import REPORTS_DIR
from shadowportx.db.base import get_session, utcnow
from shadowportx.engines import reporting

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/security")
async def security_report(
    fmt: str = "json",
    ctx: Context = Depends(get_context),
    session: AsyncSession = Depends(get_session),
):
    data = await reporting.gather_report_data(session, ctx.org_id)
    fmt = fmt.lower()
    if fmt == "json":
        return JSONResponse(data)
    if fmt == "csv":
        return PlainTextResponse(reporting.render_csv_findings(data), media_type="text/csv",
                                 headers={"Content-Disposition": "attachment; filename=shadowportx_findings.csv"})
    if fmt == "html":
        return HTMLResponse(reporting.render_html(data))
    if fmt == "pdf":
        ts = utcnow().strftime("%Y%m%d_%H%M%S")
        path = str(REPORTS_DIR / f"shadowportx_report_{ts}.pdf")
        reporting.render_pdf(data, path)
        return FileResponse(path, media_type="application/pdf",
                            filename=f"shadowportx_report_{ts}.pdf")
    return JSONResponse({"error": "unsupported format", "supported": ["json", "csv", "html", "pdf"]},
                        status_code=400)
