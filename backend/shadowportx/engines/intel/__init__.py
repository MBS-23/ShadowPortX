"""Vulnerability intelligence engine: CPE mapping and CVE correlation.

Correlation != exploitation. This engine states that *public vulnerability information
exists* for a detected product/version. Whether an asset is actually affected still
requires verification (see the verification engine and finding states).
"""

from shadowportx.engines.intel.cve import CVECorrelator

__all__ = ["CVECorrelator"]
