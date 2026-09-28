"""Safe proof-of-concept (L3) tests.

Drives the checks against an in-process ASGI app (via httpx ASGITransport) that simulates
both vulnerable and clean web surfaces — no real network, fully deterministic. Confirms the
probes detect real exposures and, crucially, produce NO false positives on a clean app.
"""

import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Route

from shadowportx.core import enums
from shadowportx.engines.verification import safe_poc

_REDIRECT_PARAMS = ("next", "url", "redirect", "return", "dest", "continue")


async def _root(request):
    for p in _REDIRECT_PARAMS:
        if p in request.query_params:
            return RedirectResponse(request.query_params[p], status_code=302)
    headers = {}
    origin = request.headers.get("origin")
    if origin:
        headers["Access-Control-Allow-Origin"] = origin
        headers["Access-Control-Allow-Credentials"] = "true"
    return HTMLResponse("<html><body>ok</body></html>", headers=headers)


def _vulnerable_app():
    return Starlette(routes=[
        Route("/", _root),
        Route("/.git/HEAD", lambda r: PlainTextResponse("ref: refs/heads/main\n")),
        Route("/.env", lambda r: PlainTextResponse("APP_KEY=base64:abcd\nDB_PASSWORD=s3cret\n",
                                                   media_type="text/plain")),
        Route("/actuator/env", lambda r: JSONResponse({"propertySources": [{"name": "systemEnvironment"}]})),
    ])


def _clean_app():
    async def clean_root(request):
        for p in _REDIRECT_PARAMS:
            if p in request.query_params:  # ignores the param — no redirect
                return HTMLResponse("<html><body>home</body></html>")
        return HTMLResponse("<html><body>home</body></html>")

    async def not_found(request):
        return PlainTextResponse("Not Found", status_code=404)

    return Starlette(routes=[
        Route("/", clean_root),
        Route("/.git/HEAD", not_found),
        Route("/.env", not_found),
        Route("/actuator/env", not_found),
    ])


async def _probe(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://mock") as client:
        return await safe_poc.probe(client, "http://mock")


@pytest.mark.asyncio
async def test_detects_vulnerable_surface():
    results = await _probe(_vulnerable_app())
    conditions = {r.condition for r in results}
    assert "exposed-git-repository" in conditions
    assert "exposed-dotenv-file" in conditions
    assert "cors-reflects-arbitrary-origin-with-credentials" in conditions
    assert "open-redirect" in conditions
    assert "spring-actuator-env-exposed" in conditions
    # Every result is safe, read-only, and evidence-bearing.
    for r in results:
        assert r.verified is True
        assert r.evidence.get("safe") is True
        assert "L3" in r.evidence.get("method", "")
        assert r.severity in (enums.Severity.MEDIUM, enums.Severity.HIGH)


@pytest.mark.asyncio
async def test_no_false_positives_on_clean_surface():
    results = await _probe(_clean_app())
    assert results == []


@pytest.mark.asyncio
async def test_git_evidence_has_report_ready_probe():
    results = await _probe(_vulnerable_app())
    git = next(r for r in results if r.condition == "exposed-git-repository")
    assert git.evidence["probe"] == "GET /.git/HEAD"
    assert git.evidence["response_snippet"].startswith("ref:")
    assert git.recommendation
