"""Fast, resilient infrastructure probe across stratified cohorts."""

import datetime
import json
import socket
import ssl
import sys
import time
from urllib.parse import urlparse
import numpy as np
import pandas as pd
import requests

def extract_apex(url):
    try:
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
        host = urlparse(url).netloc.split(":")[0].lower().strip()
        if host.startswith("www."):
            host = host[4:]
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        two_part = f"{parts[-2]}.{parts[-1]}"
        if two_part in {"co.uk", "ac.uk", "gov.uk", "ac.in", "edu.in", "gov.in", "co.in", "com.au", "net.au", "co.jp", "com.br", "co.za"}:
            return f"{parts[-3]}.{two_part}"
        return f"{parts[-2]}.{parts[-1]}"
    except Exception:
        return url

def fast_probe_tls(hostname: str, timeout: float = 1.5):
    t0 = time.perf_counter()
    res = {
        "tls_ok": False,
        "cert_age_days": None,
        "total_days": None,
        "is_short_90d": False,
        "is_lets_encrypt": False,
        "issuer": "None",
        "sans_count": 0,
        "is_wildcard": False,
        "lat_ms": 0.0
    }
    clean_host = hostname.split(":")[0].strip()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((clean_host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean_host) as ssock:
                t1 = time.perf_counter()
                res["lat_ms"] = round((t1 - t0) * 1000, 2)
                res["tls_ok"] = True
                
                # Now fetch decoded cert with standard context if possible
                try:
                    ctx_dec = ssl.create_default_context()
                    with socket.create_connection((clean_host, 443), timeout=timeout) as sock2:
                        with ctx_dec.wrap_socket(sock2, server_hostname=clean_host) as ssock2:
                            c = ssock2.getpeercert()
                            if c:
                                fmt = "%b %d %H:%M:%S %Y %Z"
                                dt_b = datetime.datetime.strptime(c["notBefore"], fmt).replace(tzinfo=datetime.timezone.utc)
                                dt_a = datetime.datetime.strptime(c["notAfter"], fmt).replace(tzinfo=datetime.timezone.utc)
                                now = datetime.datetime.now(datetime.timezone.utc)
                                age = (now - dt_b).total_seconds() / 86400.0
                                tot = (dt_a - dt_b).total_seconds() / 86400.0
                                res["cert_age_days"] = round(max(0.0, age), 1)
                                res["total_days"] = round(tot, 1)
                                res["is_short_90d"] = tot <= 100
                                for item in c.get("issuer", []):
                                    for k, v in item:
                                        if k == "organizationName":
                                            res["issuer"] = v
                                            if "Let's Encrypt" in v:
                                                res["is_lets_encrypt"] = True
                                sans = [v for t, v in c.get("subjectAltName", []) if t == "DNS"]
                                res["sans_count"] = len(sans)
                                for san in sans:
                                    if san.startswith("*."):
                                        res["is_wildcard"] = True
                except Exception:
                    pass
    except Exception:
        t1 = time.perf_counter()
        res["lat_ms"] = round((t1 - t0) * 1000, 2)
    return res

def fast_probe_dns(hostname: str):
    t0 = time.perf_counter()
    res = {"dns_ok": False, "ips": 0, "ptr": "None", "ptr_match": False, "lat_ms": 0.0}
    clean_host = hostname.split(":")[0].strip()
    try:
        _, _, ip_list = socket.gethostbyname_ex(clean_host)
        t1 = time.perf_counter()
        res["lat_ms"] = round((t1 - t0) * 1000, 2)
        res["dns_ok"] = True
        res["ips"] = len(ip_list)
        if ip_list:
            try:
                ptr_name, _, _ = socket.gethostbyaddr(ip_list[0])
                res["ptr"] = ptr_name
                if clean_host in ptr_name or ptr_name.endswith(f".{clean_host}"):
                    res["ptr_match"] = True
            except Exception:
                res["ptr"] = "no_ptr"
    except Exception:
        t1 = time.perf_counter()
        res["lat_ms"] = round((t1 - t0) * 1000, 2)
    return res

def fast_probe_rdap(domain: str, timeout: float = 2.0):
    t0 = time.perf_counter()
    res = {"rdap_ok": False, "dom_age_days": None, "lat_ms": 0.0}
    try:
        url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(url, timeout=timeout, headers={"Accept": "application/rdap+json", "User-Agent": "PhishGuard-Diag/1.0"})
        t1 = time.perf_counter()
        res["lat_ms"] = round((t1 - t0) * 1000, 2)
        if resp.status_code == 200:
            res["rdap_ok"] = True
            data = resp.json()
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration":
                    dt_str = ev.get("eventDate", "")
                    if dt_str:
                        dt_clean = dt_str.replace("Z", "+00:00")[:19]
                        dt_reg = datetime.datetime.fromisoformat(dt_clean).replace(tzinfo=datetime.timezone.utc)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        res["dom_age_days"] = round((now - dt_reg).total_seconds() / 86400.0, 1)
                        break
    except Exception:
        t1 = time.perf_counter()
        res["lat_ms"] = round((t1 - t0) * 1000, 2)
    return res

COHORTS = [
    # Cohort 1: Established Enterprise Portals
    {"name": "Google Accounts", "host": "accounts.google.com", "dom": "google.com", "strata": "1. Established Legit"},
    {"name": "Microsoft SSO", "host": "login.microsoftonline.com", "dom": "microsoftonline.com", "strata": "1. Established Legit"},
    {"name": "GitHub Auth", "host": "github.com", "dom": "github.com", "strata": "1. Established Legit"},
    {"name": "Wikipedia", "host": "en.wikipedia.org", "dom": "wikipedia.org", "strata": "1. Established Legit"},
    {"name": "Bannari College", "host": "ps.bitsathy.ac.in", "dom": "bitsathy.ac.in", "strata": "1. Established Legit"},
    
    # Cohort 2: Legitimate Newly-Registered Domains & Modern Startups / SaaS
    {"name": "Dub.co (URL Hub)", "host": "dub.co", "dom": "dub.co", "strata": "2. Legit New/Startup"},
    {"name": "Cursor AI IDE", "host": "www.cursor.com", "dom": "cursor.com", "strata": "2. Legit New/Startup"},
    {"name": "Cal.com Scheduling", "host": "cal.com", "dom": "cal.com", "strata": "2. Legit New/Startup"},
    {"name": "Linear App", "host": "linear.app", "dom": "linear.app", "strata": "2. Legit New/Startup"},
    {"name": "Resend Email API", "host": "resend.com", "dom": "resend.com", "strata": "2. Legit New/Startup"},
    {"name": "Vercel Deployments", "host": "nextjs.org", "dom": "nextjs.org", "strata": "2. Legit New/Startup"},
    
    # Cohort 3: High-Link Phishing Clones & PaaS-Hosted Attacks
    {"name": "Netlify Cloned Lure", "host": "avocent.netlify.app", "dom": "netlify.app", "strata": "3. Phish (Cloned PaaS)"},
    {"name": "Pages.dev Crypto Lure", "host": "da51ca.pages.dev", "dom": "pages.dev", "strata": "3. Phish (Cloned PaaS)"},
    {"name": "Replit Banking Lure", "host": "credi-en-linia--ecu-emprende.replit.app", "dom": "replit.app", "strata": "3. Phish (Cloned PaaS)"},
    
    # Cohort 4: Disposable / Newly Registered Phishing Spoof Domains
    {"name": "AppleID Spoof Lure", "host": "appleid.verify-security-checkpoint.top", "dom": "verify-security-checkpoint.top", "strata": "4. Phish (Spoofed Domain)"},
    {"name": "IRS Tax Refund Lure", "host": "irs-tax-refund-gov.site", "dom": "irs-tax-refund-gov.site", "strata": "4. Phish (Spoofed Domain)"},
]

print("=" * 105)
print(f"{'Target Name':<24} | {'Strata':<22} | {'Dom Age (d)':<12} | {'Cert Age (d)':<12} | {'90d Cert?':<9} | {'LetEncrypt?':<11} | {'DNS IPs':<7} | {'PTR Match':<9}")
print("=" * 105)

all_records = []
for c in COHORTS:
    t_tls = fast_probe_tls(c["host"])
    t_dns = fast_probe_dns(c["host"])
    t_rdap = fast_probe_rdap(c["dom"])
    
    d_age = str(t_rdap["dom_age_days"]) if t_rdap["dom_age_days"] is not None else "N/A"
    c_age = str(t_tls["cert_age_days"]) if t_tls["cert_age_days"] is not None else "N/A"
    short_c = "YES" if t_tls["is_short_90d"] else "NO"
    le = "YES" if t_tls["is_lets_encrypt"] else "NO"
    ptr_m = "YES" if t_dns["ptr_match"] else "NO"
    
    print(f"{c['name']:<24} | {c['strata']:<22} | {d_age:<12} | {c_age:<12} | {short_c:<9} | {le:<11} | {t_dns['ips']:<7} | {ptr_m:<9}")
    
    all_records.append({
        "name": c["name"],
        "strata": c["strata"],
        "tls_lat": t_tls["lat_ms"],
        "dns_lat": t_dns["lat_ms"],
        "rdap_lat": t_rdap["lat_ms"]
    })

print("=" * 105)

tls_l = [r["tls_lat"] for r in all_records if r["tls_lat"] > 0]
dns_l = [r["dns_lat"] for r in all_records if r["dns_lat"] > 0]
rdap_l = [r["rdap_lat"] for r in all_records if r["rdap_lat"] > 0]

print(f"\n[LATENCY BENCHMARKS]")
print(f"  DNS Latency:  Mean={np.mean(dns_l):.1f}ms | Median={np.median(dns_l):.1f}ms | Max={np.max(dns_l):.1f}ms")
print(f"  TLS Latency:  Mean={np.mean(tls_l):.1f}ms | Median={np.median(tls_l):.1f}ms | Max={np.max(tls_l):.1f}ms")
print(f"  RDAP Latency: Mean={np.mean(rdap_l):.1f}ms | Median={np.median(rdap_l):.1f}ms | Max={np.max(rdap_l):.1f}ms")
