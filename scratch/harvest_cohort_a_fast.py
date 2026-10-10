"""Fast, robust registration-first harvester for Cohort A (Legitimate Young Domains <14 days old).

Queries Certificate Transparency logs and recently registered domain feeds,
cross-references RDAP for strict age < 14 days, and applies legitimacy verification.
"""

import datetime
import json
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import pandas as pd
import requests

REPO_ROOT = Path("c:/Users/Udhaya/S5_Phishing_Detector").resolve()
BACKEND_DIR = REPO_ROOT / "backend"
COHORT_DIR = BACKEND_DIR / "data" / "young_domain_cohort"
COHORT_DIR.mkdir(parents=True, exist_ok=True)
COHORT_A_CSV = COHORT_DIR / "cohort_a_legitimate_young_domains.csv"
EXCLUSION_LOG_PATH = COHORT_DIR / "cohort_a_exclusions.log"

CUTOFF_DATE = datetime.datetime(2026, 8, 25, 0, 0, 0, tzinfo=datetime.timezone.utc)
NOW = datetime.datetime(2026, 9, 8, 15, 40, 0, tzinfo=datetime.timezone.utc)

PAAS_DOMAINS = {
    "pages.dev", "netlify.app", "github.io", "vercel.app", "firebaseapp.com",
    "render.com", "glitch.me", "surge.sh", "blogspot.com", "wordpress.com",
    "wixsite.com", "weebly.com", "000webhostapp.com", "sites.google.com",
    "s3.amazonaws.com", "blob.core.windows.net", "dub.sh", "replit.app",
    "fly.dev", "railway.app", "deno.dev", "web.app", "duckdns.org", "ngrok.io",
    "loca.lt", "trycloudflare.com", "tinyurl.com", "bit.ly", "t.co"
}

PARKING_KEYWORDS = [
    "buy this domain", "domain for sale", "parked free", "godaddy", "sedoparking",
    "dan.com", "namecheap parking", "hugedomains", "inquire about this domain",
    "domain has been registered", "under construction", "coming soon placeholder",
    "renew your domain", "parked domain", "bodis.com"
]

PHISH_KEYWORDS = [
    "paypal", "chase", "wellsfargo", "bankofamerica", "metamask", "binance",
    "trustwallet", "coinbase", "appleid", "icloud-verify", "netflix-billing",
    "steam-community", "roblox-redeem", "security-alert", "irs-tax", "usps-tracking",
    "wallet-connect", "ledger-auth", "secure-login"
]

def extract_apex(hostname: str) -> str:
    host = hostname.lower().strip()
    if ":" in host:
        host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_part_tlds = {
        "co.uk", "ac.uk", "gov.uk", "ac.in", "gov.in", "co.in", "edu.in",
        "com.au", "net.au", "co.jp", "com.br", "co.za"
    }
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in two_part_tlds and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}"
    return f"{parts[-2]}.{parts[-1]}"

def query_rdap(domain: str, timeout: float = 2.5) -> Tuple[Optional[str], Optional[float], str]:
    try:
        url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"Accept": "application/rdap+json", "User-Agent": "PhishGuard-CohortA-Harvester/1.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration":
                    dt_str = ev.get("eventDate", "")
                    if dt_str:
                        dt_clean = dt_str.replace("Z", "+00:00")[:19]
                        dt_reg = datetime.datetime.fromisoformat(dt_clean).replace(tzinfo=datetime.timezone.utc)
                        age_days = round(max(0.0, (NOW - dt_reg).total_seconds() / 86400.0), 1)
                        return dt_clean, age_days, "success"
            return None, None, "no_registration_event"
        elif resp.status_code == 429:
            return None, None, "http_429"
        elif resp.status_code == 404:
            return None, None, "http_404"
        else:
            return None, None, f"http_{resp.status_code}"
    except requests.exceptions.Timeout:
        return None, None, "timeout"
    except Exception as e:
        return None, None, f"error_{type(e).__name__}"

def check_site_legitimacy(url: str, timeout: float = 2.5) -> Tuple[bool, str, Optional[str]]:
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        if resp.status_code not in (200, 301, 302, 307, 308):
            return False, f"http_{resp.status_code}", None
        
        text = resp.text.lower()
        
        # Check parking markers
        for kw in PARKING_KEYWORDS:
            if kw in text:
                return False, f"parked_domain ({kw})", None
                
        # Check phishing / brand spoof markers
        for kw in PHISH_KEYWORDS:
            if kw in text:
                return False, f"suspicious_keyword ({kw})", None
                
        if len(resp.text.strip()) < 100:
            return False, "empty_page", None
            
        m_title = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        title_str = m_title.group(1).strip() if m_title else "Clean Web Page"
        title_clean = re.sub(r"\s+", " ", title_str)[:60]
        
        return True, "legitimate_coherent_content", title_clean
    except Exception as e:
        return False, f"fetch_error_{type(e).__name__}", None

print("=" * 90)
print("COHORT A: REGISTRATION-DATE-FIRST SOURCING PIPELINE")
print("=" * 90)

# Targeted search seeds across legitimate personal, portfolio, developer, and event domains
TARGETED_SEEDS = [
    "hackathon.org", "devclub.io", "studio.design", "portfolio.me",
    "event2026.com", "lab.tech", "craft.studio", "cafe.app",
    "digital.solutions", "agency.media", "creative.space", "ai-lab.dev",
    "maker.sh", "developer.community", "opensource.tools", "student.org",
    "research.group", "robotics.club", "design.works", "localbiz.net"
]

candidate_domains = set()

print("\n[PHASE 1] COLLECTING RECENTLY ISSUED APEX CERTIFICATES VIA CRt.sh...")
for seed in TARGETED_SEEDS:
    try:
        url = f"https://crt.sh/?q={seed}&output=json"
        resp = requests.get(url, timeout=4.0)
        if resp.status_code == 200:
            data = resp.json()
            found = 0
            for item in data[:40]:
                nb = item.get("not_before", "")
                if nb:
                    try:
                        dt = datetime.datetime.fromisoformat(nb).replace(tzinfo=datetime.timezone.utc)
                        if dt >= CUTOFF_DATE:
                            for n in item.get("name_value", "").split("\n"):
                                n = n.strip()
                                if n and not n.startswith("*"):
                                    apex = extract_apex(n)
                                    if apex not in PAAS_DOMAINS and "." in apex and len(apex) > 4:
                                        candidate_domains.add(apex)
                                        found += 1
                    except Exception:
                        pass
            print(f"  - Seed '{seed:<20}': Found {found} recent cert candidates")
        time.sleep(0.2)
    except Exception as e:
        print(f"  - Seed '{seed:<20}': Error ({e})")

print(f"\n--> Extracted {len(candidate_domains)} Candidate Apex Domains issued in last 14 days.")

# -----------------------------------------------------------------------------
# PHASE 2: RDAP VERIFICATION & LEGITIMACY AUDIT
# -----------------------------------------------------------------------------
print("\n[PHASE 2] CROSS-REFERENCING RDAP REGISTRATION DATES & LEGITIMACY REVIEW...")

verified_cohort_a = []
exclusions = []
rdap_total = 0
rdap_success = 0
rdap_fail = 0

candidates_list = sorted(list(candidate_domains))

for domain in candidates_list:
    rdap_total += 1
    reg_date, age_days, status = query_rdap(domain, timeout=2.5)
    time.sleep(0.12)
    
    if status == "success" and age_days is not None:
        rdap_success += 1
        if age_days < 14.0:
            site_url = f"https://{domain}"
            is_legit, reason, title = check_site_legitimacy(site_url, timeout=2.5)
            
            if is_legit:
                purpose = f"New {domain.split('.')[-1]} domain | {title}"
                record = {
                    "url": site_url,
                    "apex_domain": domain,
                    "rdap_registration_date": reg_date,
                    "registration_age_days": age_days,
                    "purpose_note": purpose,
                    "source": "Certificate Transparency Log & RDAP Verification",
                    "verification_status": "verified_legitimate_young_domain"
                }
                verified_cohort_a.append(record)
                print(f"  [OK] VERIFIED: {domain:<28} | Age: {age_days:>4.1f}d | Title: {str(title)[:35]}")
                if len(verified_cohort_a) >= 25:
                    break
            else:
                exclusions.append({"domain": domain, "age_days": age_days, "reason": reason})
                print(f"  [EXCLUDE] CONTENT: {domain:<26} | Age: {age_days:>4.1f}d | Reason: {reason}")
        else:
            exclusions.append({"domain": domain, "age_days": age_days, "reason": "age_ge_14_days (renewed older domain)"})
    else:
        rdap_fail += 1
        exclusions.append({"domain": domain, "age_days": None, "reason": f"rdap_{status}"})

# Save results
df_res = pd.DataFrame(verified_cohort_a)
df_res.to_csv(COHORT_A_CSV, index=False)
print(f"\n--> Written {len(df_res)} records to {COHORT_A_CSV}")

with open(EXCLUSION_LOG_PATH, "w", encoding="utf-8") as f:
    for exc in exclusions:
        f.write(json.dumps(exc) + "\n")

print("\n" + "=" * 90)
print("COHORT A HARVESTING COMPLETE")
print("=" * 90)
print(f"Total Candidates Probed:       {rdap_total}")
print(f"RDAP Resolution Rate:          {rdap_success}/{rdap_total} ({rdap_success/rdap_total*100:.1f}%)" if rdap_total else 0)
print(f"RDAP Failures:                 {rdap_fail}/{rdap_total} ({rdap_fail/rdap_total*100:.1f}%)" if rdap_total else 0)
print(f"Final Verified Cohort A (<14d): {len(df_res)} records")
if not df_res.empty:
    print(f"Age Range:                     Min={df_res['registration_age_days'].min():.1f}d | Median={df_res['registration_age_days'].median():.1f}d | Max={df_res['registration_age_days'].max():.1f}d")
    print(f"Registration Date Span:        {df_res['rdap_registration_date'].min()[:10]} to {df_res['rdap_registration_date'].max()[:10]}")
print("=" * 90)
