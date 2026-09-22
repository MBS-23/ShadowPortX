import whois
import logging
import socket
import ssl
import dns.resolver
from datetime import datetime
from utils.resource_path import resource_path
import os
# -------------------------------
# Logger Setup
# -------------------------------
logging.basicConfig(
    filename=resource_path("logs/whois_lookup.log"),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log_path = resource_path("logs/whois_lookup.log")
os.makedirs(os.path.dirname(log_path), exist_ok=True)
# -------------------------------
# WHOIS Lookup
# -------------------------------
def _safe_whois(domain):
    try:
        return whois.whois(domain)
    except Exception as e:
        logging.error(f"[WHOIS] Lookup failed for {domain}: {e}")
        return None

def get_whois_info(domain):
    data = _safe_whois(domain)
    if not data:
        return {'error': f"WHOIS lookup failed for {domain}"}
    return {
        'domain_name': getattr(data, 'domain_name', None),
        'registrar': getattr(data, 'registrar', None),
        'creation_date': str(getattr(data, 'creation_date', None)),
        'expiration_date': str(getattr(data, 'expiration_date', None)),
        'name_servers': getattr(data, 'name_servers', None),
        'status': getattr(data, 'status', None),
        'emails': getattr(data, 'emails', None) or "Hidden"
    }

def print_whois_summary(domain):
    data = _safe_whois(domain)
    if not data:
        return f"❌ WHOIS lookup failed for {domain}"

    return f"""
🗂️ WHOIS Summary:
📛 Domain Name     : {data.domain_name}
🏢 Registrar       : {data.registrar}
📅 Created On      : {data.creation_date}
📆 Expires On      : {data.expiration_date}
🧭 Name Servers    : {data.name_servers}
📮 Contact Emails  : {data.emails or 'Hidden'}
🗺️ Status          : {data.status}
"""

# -------------------------------
# DNS Record Lookup
# -------------------------------
def get_dns_records(domain):
    records = {}
    try:
        for rtype in ["A", "AAAA", "MX", "NS", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(a) for a in answers]
            except:
                records[rtype] = []
    except Exception as e:
        records["error"] = f"DNS lookup failed: {e}"
    return records

# -------------------------------
# 🔐 SSL Certificate Info
# -------------------------------
def get_ssl_info(domain, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "notBefore": cert.get("notBefore"),
                    "notAfter": cert.get("notAfter"),
                    "serialNumber": cert.get("serialNumber")
                }
    except Exception as e:
        return {"error": f"SSL cert check failed: {e}"}

# -------------------------------
# CLI Testing (Optional)
# -------------------------------
if __name__ == "__main__":
    domain = input("Enter domain/IP: ").strip()
    print(print_whois_summary(domain))
    print(get_dns_records(domain))
    ssl_data = get_ssl_info(domain)
    print("SSL Info:", ssl_data)
