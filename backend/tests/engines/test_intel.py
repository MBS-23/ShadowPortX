from shadowportx.engines.intel import CVECorrelator
from shadowportx.engines.intel.cpe import normalize_version
from shadowportx.engines.results import ServiceInfo

corr = CVECorrelator()


def test_openssh_regresssion_matches():
    vulns = corr.correlate(ServiceInfo(name="ssh", product="OpenSSH", version="8.9p1"))
    assert any(v.cve_id == "CVE-2024-6387" for v in vulns)


def test_patched_openssh_has_no_cve():
    # 9.9 is >= 9.8 (fixed) and above all seed constraints.
    assert corr.correlate(ServiceInfo(product="OpenSSH", version="9.9")) == []


def test_apache_2449_matches_multiple():
    vulns = corr.correlate(ServiceInfo(product="Apache httpd", version="2.4.49"))
    assert len(vulns) >= 2
    assert any(v.exploit_known for v in vulns)


def test_results_sorted_by_cvss_desc():
    vulns = corr.correlate(ServiceInfo(product="Apache httpd", version="2.4.49"))
    scores = [v.cvss_score or 0 for v in vulns]
    assert scores == sorted(scores, reverse=True)


def test_version_normalization():
    assert str(normalize_version("8.9p1")) == "8.9.1"
    assert str(normalize_version("1.3.5a")) == "1.3.5"
    assert normalize_version(None) is None


def test_unknown_product_no_match():
    assert corr.correlate(ServiceInfo(product="TotallyMadeUp", version="1.0")) == []
