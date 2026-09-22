"""TLS/certificate security analysis.

Retrieves the leaf certificate, parses it with ``cryptography`` (subject/issuer/SANs/
validity/expiry/key size/signature algorithm), fingerprints it, and probes which TLS
protocol versions the endpoint negotiates. All read-only.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from shadowportx.engines.results import CertInfo

_TLS_VERSIONS = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}
_WEAK_VERSIONS = {"TLSv1.0", "TLSv1.1"}


def _name_str(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _fetch_cert_der(host: str, port: int, timeout: float) -> bytes | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True)


def _probe_version(host: str, port: int, name: str, ver: ssl.TLSVersion, timeout: float) -> str | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ver
        ctx.maximum_version = ver
    except ValueError:
        return None  # runtime/OpenSSL doesn't support pinning this version
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return name
    except Exception:
        return None


def _key_bits(cert: x509.Certificate) -> int | None:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub.curve.key_size
    return getattr(pub, "key_size", None)


def _blocking_analyze(host: str, port: int, timeout: float) -> CertInfo | None:
    der = _fetch_cert_der(host, port, timeout)
    if not der:
        return None
    cert = x509.load_der_x509_certificate(der)

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    now = datetime.now(UTC)
    days_left = (not_after - now).days
    is_valid = not_before <= now <= not_after

    versions = [
        v for v, name in (
            (_probe_version(host, port, n, ver, timeout), n)
            for n, ver in _TLS_VERSIONS.items()
        ) if v
    ]

    return CertInfo(
        subject=_name_str(cert.subject),
        issuer=_name_str(cert.issuer),
        serial=format(cert.serial_number, "x"),
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        sans=sans,
        signature_algorithm=cert.signature_algorithm_oid._name,
        key_bits=_key_bits(cert),
        tls_versions=versions,
        is_valid=is_valid,
        fingerprint_sha256=hashlib.sha256(der).hexdigest(),
        days_until_expiry=days_left,
    )


async def analyze(host: str, port: int = 443, timeout: float = 6.0) -> CertInfo | None:
    try:
        return await asyncio.to_thread(_blocking_analyze, host, port, timeout)
    except Exception:
        return None


def weak_tls_versions(cert: CertInfo) -> list[str]:
    return [v for v in cert.tls_versions if v in _WEAK_VERSIONS]
