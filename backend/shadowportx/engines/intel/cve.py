"""CVE correlation: match a detected product/version against known-vulnerability intel.

Loads the offline seed dataset once. Matching rules:
* product + vendor must match (case-insensitive) the detected CPE/product,
* the detected version must satisfy the CVE's affected specifier (empty specifier = the
  vulnerability is version-independent, e.g. a protocol flaw).

A match means "public intelligence exists for this version" — surfaced as a
POTENTIALLY_AFFECTED finding, not a confirmed compromise.
"""

from __future__ import annotations

import json
from functools import lru_cache

from packaging.specifiers import InvalidSpecifier, SpecifierSet

from shadowportx.core import enums
from shadowportx.core.config import DATA_DIR
from shadowportx.engines.intel.cpe import CPE, normalize_version, parse_cpe
from shadowportx.engines.results import CorrelatedVuln, ServiceInfo

# Aliases so a detected product name maps onto the CPE product token in the dataset.
_PRODUCT_ALIASES = {
    "nginx": ("nginx", "nginx"),
    "apache httpd": ("apache", "http_server"),
    "apache": ("apache", "http_server"),
    "openssh": ("openbsd", "openssh"),
    "ssh": ("openbsd", "openssh"),
    "tomcat": ("apache", "tomcat"),
    "redis": ("redis", "redis"),
    "exim": ("exim", "exim"),
    "vsftpd": ("vsftpd_project", "vsftpd"),
    "proftpd": ("proftpd", "proftpd"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "php": ("php", "php"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "openssl": ("openssl", "openssl"),
}


@lru_cache(maxsize=1)
def _load_seed() -> list[dict]:
    path = DATA_DIR / "cve_seed.json"
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f).get("cves", [])


def _resolve_cpe(service: ServiceInfo) -> CPE | None:
    cpe = parse_cpe(service.cpe)
    if cpe:
        return cpe
    key = (service.product or service.name or "").strip().lower()
    if key in _PRODUCT_ALIASES:
        vendor, product = _PRODUCT_ALIASES[key]
        return CPE(vendor=vendor, product=product, version=service.version)
    return None


def _version_affected(version_str: str | None, affected_spec: str) -> bool:
    if not affected_spec:
        return True  # version-independent (e.g. protocol-level) vulnerability
    version = normalize_version(version_str)
    if version is None:
        return False
    try:
        return version in SpecifierSet(affected_spec)
    except InvalidSpecifier:
        return False


class CVECorrelator:
    def __init__(self, dataset: list[dict] | None = None):
        self._cves = dataset if dataset is not None else _load_seed()

    def correlate(self, service: ServiceInfo) -> list[CorrelatedVuln]:
        cpe = _resolve_cpe(service)
        if not cpe:
            return []
        matches: list[CorrelatedVuln] = []
        for entry in self._cves:
            if entry["vendor"].lower() != cpe.vendor.lower():
                continue
            if entry["product"].lower() != cpe.product.lower():
                continue
            if not _version_affected(cpe.version, entry.get("affected", "")):
                continue
            matches.append(
                CorrelatedVuln(
                    cve_id=entry["cve_id"],
                    cvss_score=entry.get("cvss_score"),
                    severity=enums.Severity(entry.get("severity", "info")),
                    description=entry.get("title") or entry.get("description"),
                    cpe_match=cpe.to_string(),
                    exploit_known=bool(entry.get("exploit_known")),
                    references=entry.get("references", []),
                )
            )
        matches.sort(key=lambda v: v.cvss_score or 0, reverse=True)
        return matches
