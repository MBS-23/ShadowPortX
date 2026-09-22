from shadowportx.engines.scanner.service_detector import detect


def test_openssh_version_and_cpe():
    s = detect(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4")
    assert s.name == "ssh" and s.product == "OpenSSH" and s.version == "8.9p1"
    assert s.confidence.value == "high"
    assert "openssh" in (s.cpe or "")


def test_nginx_via_header():
    s = detect(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n")
    assert s.name == "http" and s.product == "nginx" and s.version == "1.18.0"


def test_redis_noauth_banner():
    s = detect(6379, "-NOAUTH Authentication required.")
    assert s.name == "redis"


def test_application_fingerprint_layered():
    s = detect(8080, "HTTP/1.1 403\r\nServer: nginx\r\nX-Jenkins: 2.4\r\n\r\n")
    assert s.evidence.get("application") == "Jenkins"


def test_no_banner_falls_back_to_port():
    s = detect(6379, None)
    assert s.name == "redis" and s.confidence.value == "low"


def test_unknown_banner_records_evidence():
    s = detect(4711, "SOME RANDOM BANNER")
    assert s.confidence.value == "low"
    assert "banner_excerpt" in s.evidence
