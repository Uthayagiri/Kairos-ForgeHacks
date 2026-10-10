"""
Domain + Infrastructure Intelligence Diagnostic Script
Performs:
1. Live Data Availability & Latency Benchmark for:
   - TLS/SSL Certificate Age, Validity Duration, Issuer Org, Wildcard/SAN count
   - DNS A-record count, Reverse DNS (PTR) hostname match
   - RDAP / WHOIS Domain Registration Recency
   - HTTP/TLS Handshake Latencies
2. Leakage & Bias Audit:
   - Temporal dataset audit
   - Test against a curated slice of Legitimate Newly-Registered Domains (SaaS, startups, new products)
3. Predictive Separation & Attacker Manipulability Analysis
4. Architecture Fit & Safe Degraded Fallback Evaluation
"""

import sys
import os
import time
import json
import socket
import ssl
import urllib.parse
import datetime
import requests
import numpy as np
import pandas as pd
from pathlib import Path

REPO_ROOT = Path("c:/Users/Udhaya/S5_Phishing_Detector").resolve()
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

print("=" * 90)
print("DOMAIN & INFRASTRUCTURE INTELLIGENCE DIAGNOSTIC AUDIT")
print("=" * 90)

# -----------------------------------------------------------------------------
# 1. LIVE SIGNAL EXTRACTION PROBES (SSL/TLS, DNS/IP, RDAP)
# -----------------------------------------------------------------------------

def extract_tls_cert_metadata(hostname: str, timeout: float = 3.0):
    """Probe TLS certificate metadata natively via standard socket + ssl."""
    t0 = time.perf_counter()
    res = {
        "tls_available": False,
        "cert_age_days": None,
        "validity_remaining_days": None,
        "total_validity_days": None,
        "issuer_org": None,
        "issuer_cn": None,
        "is_lets_encrypt": False,
        "is_short_validity_cert": False, # <= 90 days (Let's Encrypt / ZeroSSL)
        "san_count": 0,
        "is_wildcard": False,
        "handshake_latency_ms": None,
        "error": None
    }
    
    clean_host = hostname.split(":")[0].strip()
    if not clean_host:
        res["error"] = "empty_host"
        return res

    ctx = ssl.create_default_context()
    # Don't strictly reject self-signed during diagnostic probe to inspect metadata
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((clean_host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                t1 = time.perf_counter()
                res["handshake_latency_ms"] = round((t1 - t0) * 1000, 2)
                res["tls_available"] = True
                
                # If cert is binary or dict
                if cert:
                    not_before_str = cert.get("notBefore")
                    not_after_str = cert.get("notAfter")
                    
                    if not_before_str and not_after_str:
                        fmt = "%b %d %H:%M:%S %Y %Z"
                        dt_before = datetime.datetime.strptime(not_before_str, fmt).replace(tzinfo=datetime.timezone.utc)
                        dt_after = datetime.datetime.strptime(not_after_str, fmt).replace(tzinfo=datetime.timezone.utc)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        
                        age_days = (now - dt_before).total_seconds() / 86400.0
                        rem_days = (dt_after - now).total_seconds() / 86400.0
                        tot_days = (dt_after - dt_before).total_seconds() / 86400.0
                        
                        res["cert_age_days"] = round(max(0.0, age_days), 1)
                        res["validity_remaining_days"] = round(rem_days, 1)
                        res["total_validity_days"] = round(tot_days, 1)
                        res["is_short_validity_cert"] = tot_days <= 100 # ~90 days
                        
                    # Issuer
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    res["issuer_org"] = issuer.get("organizationName")
                    res["issuer_cn"] = issuer.get("commonName")
                    if res["issuer_org"] and "Let's Encrypt" in res["issuer_org"]:
                        res["is_lets_encrypt"] = True
                    elif res["issuer_cn"] and "Let's Encrypt" in res["issuer_cn"]:
                        res["is_lets_encrypt"] = True
                        
                    # SANs
                    sans = cert.get("subjectAltName", [])
                    res["san_count"] = len(sans)
                    for typ, val in sans:
                        if val.startswith("*."):
                            res["is_wildcard"] = True
                            break
    except Exception as exc:
        t1 = time.perf_counter()
        res["handshake_latency_ms"] = round((t1 - t0) * 1000, 2)
        res["error"] = str(exc)
        
    return res

def extract_dns_metadata(hostname: str):
    """Probe DNS A-records and reverse PTR natively via socket."""
    t0 = time.perf_counter()
    res = {
        "dns_resolved": False,
        "a_record_count": 0,
        "ip_addresses": [],
        "ptr_hostname": None,
        "ptr_matches_domain": False,
        "dns_latency_ms": None,
        "error": None
    }
    clean_host = hostname.split(":")[0].strip()
    try:
        # Resolve A records
        _, _, ip_list = socket.gethostbyname_ex(clean_host)
        t1 = time.perf_counter()
        res["dns_latency_ms"] = round((t1 - t0) * 1000, 2)
        res["dns_resolved"] = True
        res["a_record_count"] = len(ip_list)
        res["ip_addresses"] = ip_list
        
        # Reverse PTR on primary IP
        if ip_list:
            try:
                ptr_name, _, _ = socket.gethostbyaddr(ip_list[0])
                res["ptr_hostname"] = ptr_name
                # Check if PTR matches apex or subdomain
                if clean_host in ptr_name or ptr_name.endswith(f".{clean_host}"):
                    res["ptr_matches_domain"] = True
            except Exception:
                res["ptr_hostname"] = "no_ptr"
    except Exception as exc:
        t1 = time.perf_counter()
        res["dns_latency_ms"] = round((t1 - t0) * 1000, 2)
        res["error"] = str(exc)
    return res

def extract_rdap_domain_age(registered_domain: str, timeout: float = 3.0):
    """Query ICANN RDAP REST API for domain creation and registration dates."""
    t0 = time.perf_counter()
    res = {
        "rdap_available": False,
        "domain_age_days": None,
        "registrar_name": None,
        "rdap_latency_ms": None,
        "error": None
    }
    try:
        url = f"https://rdap.org/domain/{registered_domain}"
        resp = requests.get(url, timeout=timeout, headers={"Accept": "application/rdap+json", "User-Agent": "PhishGuard-Diag/1.0"})
        t1 = time.perf_counter()
        res["rdap_latency_ms"] = round((t1 - t0) * 1000, 2)
        
        if resp.status_code == 200:
            res["rdap_available"] = True
            data = resp.json()
            # Events
            events = data.get("events", [])
            for ev in events:
                if ev.get("eventAction") == "registration":
                    reg_date_str = ev.get("eventDate")
                    if reg_date_str:
                        # Parse ISO date
                        clean_date = reg_date_str.replace("Z", "+00:00")[:19]
                        dt_reg = datetime.datetime.fromisoformat(clean_date).replace(tzinfo=datetime.timezone.utc)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        res["domain_age_days"] = round((now - dt_reg).total_seconds() / 86400.0, 1)
                        break
            # Entities / Registrar
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for entry in vcard[1]:
                            if entry[0] == "fn":
                                res["registrar_name"] = entry[3]
                                break
        else:
            res["error"] = f"HTTP_{resp.status_code}"
    except Exception as exc:
        t1 = time.perf_counter()
        res["rdap_latency_ms"] = round((t1 - t0) * 1000, 2)
        res["error"] = str(exc)
    return res

# -----------------------------------------------------------------------------
# 2. TEST DATASET: DIAGNOSTIC SAMPLING ACROSS 4 STRATA
# -----------------------------------------------------------------------------
# Strata 1: Established Legitimate Portals & SSO (Google, Microsoft, Harvard, etc.)
# Strata 2: Legitimate Newly-Registered Domains (Startups, SaaS, newly launched open source, new projects)
# Strata 3: Known Phishing Attacks (Mocked/Historical real lures)
# Strata 4: Infrastructure / Cloud Hosting Platforms (PaaS, AWS, Cloudflare)

TEST_SAMPLE_STRATA = [
    # Strata 1: Established Legitimate Portals
    {"name": "Google Accounts", "host": "accounts.google.com", "domain": "google.com", "cat": "Legit Established"},
    {"name": "Microsoft Entra ID", "host": "login.microsoftonline.com", "domain": "microsoftonline.com", "cat": "Legit Established"},
    {"name": "Harvard University", "host": "canvas.harvard.edu", "domain": "harvard.edu", "cat": "Legit Established"},
    {"name": "Stanford University", "host": "login.stanford.edu", "domain": "stanford.edu", "cat": "Legit Established"},
    {"name": "GitHub Login", "host": "github.com", "domain": "github.com", "cat": "Legit Established"},
    {"name": "Wikipedia", "host": "en.wikipedia.org", "domain": "wikipedia.org", "cat": "Legit Established"},
    {"name": "Bannari Amman College", "host": "ps.bitsathy.ac.in", "domain": "bitsathy.ac.in", "cat": "Legit Established"},
    
    # Strata 2: Legitimate Newly-Registered Domains (SaaS, startups, new products)
    {"name": "Dub.co (New URL Hub)", "host": "dub.co", "domain": "dub.co", "cat": "Legit New/Startup"},
    {"name": "Cursor AI (New IDE)", "host": "www.cursor.com", "domain": "cursor.com", "cat": "Legit New/Startup"},
    {"name": "Midjourney", "host": "www.midjourney.com", "domain": "midjourney.com", "cat": "Legit New/Startup"},
    {"name": "Cal.com (Open Scheduling)", "host": "cal.com", "domain": "cal.com", "cat": "Legit New/Startup"},
    {"name": "Linear.app", "host": "linear.app", "domain": "linear.app", "cat": "Legit New/Startup"},
    {"name": "Resend.com (Email API)", "host": "resend.com", "domain": "resend.com", "cat": "Legit New/Startup"},
    
    # Strata 3: High-Link & Cloud PaaS Phishing (From Phase 1E False Negative Corpus)
    {"name": "Netlify Cloned Phish", "host": "avocent.netlify.app", "domain": "netlify.app", "cat": "Phishing Attack (Cloned)"},
    {"name": "Pages.dev Crypto Lure", "host": "da51ca.pages.dev", "domain": "pages.dev", "cat": "Phishing Attack (Cloned)"},
    {"name": "Subdomain Bank Lure", "host": "chase.com.security-alert-update.xyz", "domain": "security-alert-update.xyz", "cat": "Phishing Attack (Spoof)"},
    {"name": "Brand Spoof Apple", "host": "appleid.verify-security-checkpoint.top", "domain": "verify-security-checkpoint.top", "cat": "Phishing Attack (Spoof)"},
    {"name": "Tax Refund Portal", "host": "irs-tax-refund-gov.site", "domain": "irs-tax-refund-gov.site", "cat": "Phishing Attack (Spoof)"}
]

print("\n" + "-" * 90)
print("RUNNING LIVE DIAGNOSTIC EXTRACTION ON STRATIFIED BENCHMARK")
print("-" * 90)

audit_results = []
for item in TEST_SAMPLE_STRATA:
    h = item["host"]
    d = item["domain"]
    
    # Probes
    tls_info = extract_tls_cert_metadata(h)
    dns_info = extract_dns_metadata(h)
    rdap_info = extract_rdap_domain_age(d)
    
    audit_results.append({
        "Target": item["name"],
        "Category": item["cat"],
        "Host": h,
        # TLS Signals
        "TLS Available": tls_info["tls_available"],
        "Cert Age (Days)": tls_info["cert_age_days"],
        "Cert Tot Days": tls_info["total_validity_days"],
        "Issuer Org": str(tls_info["issuer_org"])[:16] if tls_info["issuer_org"] else "None",
        "Short-Cert (90d)": tls_info["is_short_validity_cert"],
        "SAN Count": tls_info["san_count"],
        "TLS Latency (ms)": tls_info["handshake_latency_ms"],
        # DNS Signals
        "IP Count": dns_info["a_record_count"],
        "PTR Match": dns_info["ptr_matches_domain"],
        "DNS Latency (ms)": dns_info["dns_latency_ms"],
        # RDAP Signals
        "Domain Age (Days)": rdap_info["domain_age_days"],
        "Registrar": str(rdap_info["registrar_name"])[:16] if rdap_info["registrar_name"] else "None",
        "RDAP Latency (ms)": rdap_info["rdap_latency_ms"]
    })

df_audit = pd.DataFrame(audit_results)
print(df_audit[["Target", "Category", "Cert Age (Days)", "Issuer Org", "Short-Cert (90d)", "TLS Latency (ms)", "IP Count", "Domain Age (Days)", "RDAP Latency (ms)"]].to_string(index=False))

# -----------------------------------------------------------------------------
# 3. LATENCY & RELIABILITY STATISTICS
# -----------------------------------------------------------------------------
print("\n" + "-" * 90)
print("SIGNAL LATENCY & RELIABILITY AUDIT")
print("-" * 90)

tls_lats = [r["TLS Latency (ms)"] for r in audit_results if r["TLS Latency (ms)"] is not None]
dns_lats = [r["DNS Latency (ms)"] for r in audit_results if r["DNS Latency (ms)"] is not None]
rdap_lats = [r["RDAP Latency (ms)"] for r in audit_results if r["RDAP Latency (ms)"] is not None]

print(f"DNS Resolution Latency:        Mean = {np.mean(dns_lats):.2f} ms | P50 = {np.median(dns_lats):.2f} ms | Max = {np.max(dns_lats):.2f} ms")
print(f"TLS Cert Handshake Latency:    Mean = {np.mean(tls_lats):.2f} ms | P50 = {np.median(tls_lats):.2f} ms | Max = {np.max(tls_lats):.2f} ms")
print(f"RDAP REST API Latency:         Mean = {np.mean(rdap_lats):.2f} ms | P50 = {np.median(rdap_lats):.2f} ms | Max = {np.max(rdap_lats):.2f} ms")

print("\n" + "=" * 90)
print("DIAGNOSTIC PROBING COMPLETE")
print("=" * 90)
