"""CPE helpers and version normalization.

Real-world service versions (e.g. OpenSSH ``8.9p1``, ``1.3.5a``) are not PEP 440 clean,
so we normalize them into comparable versions before matching against CVE specifiers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version

_VERSION_TOKEN = re.compile(r"(\d+(?:\.\d+)*(?:[a-z]?\d*)?)", re.IGNORECASE)


@dataclass(frozen=True)
class CPE:
    vendor: str
    product: str
    version: str | None = None

    def to_string(self) -> str:
        return f"cpe:2.3:a:{self.vendor}:{self.product}:{self.version or '*'}:*:*:*:*:*:*:*"


def parse_cpe(cpe: str | None) -> CPE | None:
    if not cpe:
        return None
    parts = cpe.split(":")
    # cpe:2.3:a:vendor:product:version:...
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        version = parts[5] if parts[5] not in ("*", "-", "") else None
        return CPE(vendor=parts[3], product=parts[4], version=version)
    return None


def normalize_version(raw: str | None) -> Version | None:
    """Best-effort conversion of a service version string into a comparable Version.

    Examples: ``8.9p1`` -> ``8.9.1``, ``1.3.5a`` -> ``1.3.5`` (letter suffix dropped for
    ordering, since PEP 440 has no letter-patch concept), ``2.4.49`` -> ``2.4.49``.
    """
    if not raw:
        return None
    m = _VERSION_TOKEN.search(raw)
    if not m:
        return None
    token = m.group(1)
    # OpenSSH-style "8.9p1" -> "8.9.1"
    token = re.sub(r"(\d)p(\d+)", r"\1.\2", token)
    # Drop a trailing single letter (e.g. "1.3.5a" -> "1.3.5")
    token = re.sub(r"([0-9])[a-z]$", r"\1", token)
    try:
        return Version(token)
    except InvalidVersion:
        # Keep only dotted numerics as a last resort.
        numeric = ".".join(re.findall(r"\d+", token))
        try:
            return Version(numeric) if numeric else None
        except InvalidVersion:
            return None
