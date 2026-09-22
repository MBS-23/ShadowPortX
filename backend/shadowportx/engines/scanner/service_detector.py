"""Protocol-first service & version fingerprinting.

Rather than trusting the port number, we match the actual banner/response against a
signature table to identify the product and version — so a Jenkins on :8080 or an SSH on
:2222 is still identified correctly. Every detection carries *evidence* and a confidence,
never a bare assertion.

Output is a :class:`ServiceInfo` including a best-effort CPE (used later by the CVE
correlation engine).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from re import Pattern

from shadowportx.core import enums
from shadowportx.engines.results import ServiceInfo
from shadowportx.engines.scanner.ports import service_name_for


@dataclass
class Signature:
    name: str                       # service name, e.g. "http"
    product: str                    # vendor/product, e.g. "nginx"
    pattern: Pattern[str]
    version_group: int | None = 1
    cpe_vendor: str | None = None
    cpe_product: str | None = None


def _rx(p: str) -> Pattern[str]:
    return re.compile(p, re.IGNORECASE | re.MULTILINE)


# Ordered most-specific first. Patterns run against the raw banner text.
SIGNATURES: list[Signature] = [
    Signature("ssh", "OpenSSH", _rx(r"SSH-\d+\.\d+-OpenSSH[_-]([\w.]+)"), 1, "openbsd", "openssh"),
    Signature("ssh", "Dropbear", _rx(r"SSH-\d+\.\d+-dropbear[_-]?([\w.]+)?"), 1, "dropbear_ssh_project", "dropbear_ssh"),
    Signature("ssh", "SSH", _rx(r"SSH-(\d+\.\d+)-"), 1, None, None),
    Signature("http", "nginx", _rx(r"Server:\s*nginx/?([\d.]+)?"), 1, "nginx", "nginx"),
    Signature("http", "Apache httpd", _rx(r"Server:\s*Apache/?([\d.]+)?"), 1, "apache", "http_server"),
    Signature("http", "Microsoft IIS", _rx(r"Server:\s*Microsoft-IIS/?([\d.]+)?"), 1, "microsoft", "internet_information_services"),
    Signature("http", "LiteSpeed", _rx(r"Server:\s*LiteSpeed"), None, "litespeed_technologies", "litespeed"),
    Signature("http", "Caddy", _rx(r"Server:\s*Caddy"), None, "caddyserver", "caddy"),
    Signature("http", "Jetty", _rx(r"Server:\s*Jetty\(?([\d.]+)?"), 1, "eclipse", "jetty"),
    Signature("http", "Werkzeug", _rx(r"Server:\s*Werkzeug/?([\d.]+)?"), 1, "palletsprojects", "werkzeug"),
    Signature("http", "gunicorn", _rx(r"Server:\s*gunicorn/?([\d.]+)?"), 1, "gunicorn", "gunicorn"),
    Signature("http", "Kestrel", _rx(r"Server:\s*Kestrel"), None, "microsoft", "kestrel"),
    Signature("http", "Tomcat", _rx(r"(?:Apache-Coyote|Tomcat)/?([\d.]+)?"), 1, "apache", "tomcat"),
    Signature("ftp", "vsftpd", _rx(r"vsFTPd\s+([\d.]+)"), 1, "vsftpd_project", "vsftpd"),
    Signature("ftp", "ProFTPD", _rx(r"ProFTPD\s+([\d.]+)"), 1, "proftpd", "proftpd"),
    Signature("ftp", "FileZilla", _rx(r"FileZilla Server"), None, "filezilla", "filezilla_server"),
    Signature("ftp", "Pure-FTPd", _rx(r"Pure-FTPd"), None, "pureftpd", "pure-ftpd"),
    Signature("smtp", "Postfix", _rx(r"220[ -].*Postfix"), None, "postfix", "postfix"),
    Signature("smtp", "Exim", _rx(r"220[ -].*Exim\s+([\d.]+)"), 1, "exim", "exim"),
    Signature("smtp", "Sendmail", _rx(r"220[ -].*Sendmail\s+([\d.]+)"), 1, "sendmail", "sendmail"),
    Signature("redis", "Redis", _rx(r"redis_version:([\d.]+)"), 1, "redis", "redis"),
    Signature("redis", "Redis", _rx(r"-NOAUTH|^\+PONG|-DENIED|-ERR"), None, "redis", "redis"),
    Signature("memcached", "Memcached", _rx(r"VERSION\s+([\d.]+)"), 1, "memcached", "memcached"),
    Signature("mysql", "MySQL", _rx(r"\x00{0,3}([\d]+\.[\d]+\.[\d]+)[\w-]*\x00.*mysql", ), 1, "oracle", "mysql"),
    Signature("mysql", "MariaDB", _rx(r"([\d.]+)-MariaDB"), 1, "mariadb", "mariadb"),
    Signature("postgresql", "PostgreSQL", _rx(r"FATAL.*PostgreSQL|PostgreSQL\s+([\d.]+)"), 1, "postgresql", "postgresql"),
    Signature("mongodb", "MongoDB", _rx(r"MongoDB|It looks like you are trying to access MongoDB"), None, "mongodb", "mongodb"),
    Signature("elasticsearch", "Elasticsearch", _rx(r'"number"\s*:\s*"([\d.]+)"'), 1, "elastic", "elasticsearch"),
    Signature("rabbitmq", "RabbitMQ", _rx(r"RabbitMQ"), None, "pivotal_software", "rabbitmq"),
    Signature("telnet", "Telnet", _rx(r"\xff[\xfb-\xfe]"), None, None, None),
    Signature("rdp", "RDP", _rx(r"^\x03\x00\x00"), None, "microsoft", "remote_desktop"),
]

# Application fingerprints on top of an HTTP server (title/body/header hints).
_APP_HINTS: list[tuple[str, Pattern[str]]] = [
    ("Jenkins", _rx(r"X-Jenkins:|Dashboard \[Jenkins\]|jenkins")),
    ("Grafana", _rx(r"grafana|X-Grafana")),
    ("Kibana", _rx(r"kibana|kbn-name")),
    ("GitLab", _rx(r"gitlab|X-Gitlab")),
    ("phpMyAdmin", _rx(r"phpmyadmin|pma_")),
    ("WordPress", _rx(r"wp-content|wp-includes|WordPress")),
    ("Portainer", _rx(r"portainer")),
]


def _build_cpe(sig: Signature, version: str | None) -> str | None:
    if not sig.cpe_vendor or not sig.cpe_product:
        return None
    ver = version or "*"
    return f"cpe:2.3:a:{sig.cpe_vendor}:{sig.cpe_product}:{ver}:*:*:*:*:*:*:*"


def detect(port: int, banner: str | None) -> ServiceInfo:
    """Identify the service on ``port`` from its ``banner`` (protocol-first)."""
    if not banner:
        # No banner: fall back to the well-known port name, low confidence.
        name = service_name_for(port)
        return ServiceInfo(
            name=name,
            confidence=enums.Confidence.LOW,
            detection_method=enums.DetectionMethod.PORT_STATE,
            evidence={"reason": "no banner; inferred from well-known port"},
        )

    for sig in SIGNATURES:
        m = sig.pattern.search(banner)
        if not m:
            continue
        version = None
        if sig.version_group and sig.version_group <= (m.lastindex or 0):
            version = m.group(sig.version_group)
        info = ServiceInfo(
            name=sig.name,
            product=sig.product,
            version=version,
            cpe=_build_cpe(sig, version),
            confidence=enums.Confidence.HIGH if version else enums.Confidence.MEDIUM,
            detection_method=enums.DetectionMethod.PROTOCOL_FINGERPRINT
            if sig.name != "http"
            else enums.DetectionMethod.HTTP_HEADER,
            evidence={"signature": sig.product, "match": m.group(0)[:120]},
        )
        # Layer application fingerprints on top of a web server.
        if sig.name == "http":
            for app, hint in _APP_HINTS:
                if hint.search(banner):
                    info.evidence["application"] = app
                    info.product = f"{app} (on {sig.product})"
                    break
        return info

    # Unknown banner — record it as evidence at low confidence.
    return ServiceInfo(
        name=service_name_for(port),
        confidence=enums.Confidence.LOW,
        detection_method=enums.DetectionMethod.BANNER,
        evidence={"banner_excerpt": banner[:160]},
    )
