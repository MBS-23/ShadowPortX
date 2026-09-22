"""Elasticsearch verification — read-only root + _cat/indices probe (non-destructive)."""

from __future__ import annotations

import httpx

from shadowportx.core import enums
from shadowportx.engines.results import VerificationResult


async def verify(host: str, port: int, timeout: float = 6.0) -> VerificationResult | None:
    base = f"http://{host}:{port}"
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:  # nosec B501
            root = await client.get(base + "/")
            if root.status_code in (401, 403):
                return VerificationResult(
                    service="elasticsearch",
                    verified=True,
                    condition="authentication-required",
                    severity=enums.Severity.INFO,
                    confidence=enums.Confidence.HIGH,
                    evidence={"probe": "GET /", "status": root.status_code},
                    recommendation="Authentication is enforced. Keep exposure minimal.",
                )
            if root.status_code != 200:
                return None
            body = root.text
            if "cluster_name" not in body and "lucene_version" not in body:
                return None

            version = None
            try:
                version = root.json().get("version", {}).get("number")
            except Exception:
                pass

            indices = await client.get(base + "/_cat/indices?format=json")
            index_count = None
            if indices.status_code == 200:
                try:
                    index_count = len(indices.json())
                except Exception:
                    index_count = None

            return VerificationResult(
                service="elasticsearch",
                verified=True,
                condition="no-authentication-required",
                severity=enums.Severity.HIGH,
                confidence=enums.Confidence.HIGH,
                evidence={
                    "probe": "GET / and GET /_cat/indices (read-only)",
                    "observed": "Cluster metadata returned without authentication.",
                    "version": version,
                    "readable_indices": index_count,
                },
                recommendation=(
                    "Enable the Elasticsearch security features (authentication + TLS) and "
                    "restrict the HTTP port to trusted networks."
                ),
            )
    except (httpx.HTTPError, OSError):
        return None
