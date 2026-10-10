"""Targeted Young-Domain Data Collection Script.

Collects two separate held-out diagnostic cohorts:
Cohort A: Legitimate, young domains (startups, developer tools, new product launches)
Cohort B: Phishing, young, standalone domains (OpenPhish / PhishTank non-PaaS standalone lures)
"""

import datetime
import json
import os
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
COHORT_B_CSV = COHORT_DIR / "cohort_b_phishing_young_standalone_domains.csv"
RAW_PHISHING_CSV = BACKEND_DIR / "data" / "raw" / "phishing_urls.csv"

# Shared PaaS, shortener, and free hosting platforms to strictly exclude from Cohort B
PAAS_AND_SHARED_DOMAINS = {
    "pages.dev", "netlify.app", "github.io", "vercel.app", "firebaseapp.com",
    "render.com", "glitch.me", "surge.sh", "blogspot.com", "wordpress.com",
    "wixsite.com", "weebly.com", "000webhostapp.com", "sites.google.com",
    "s3.amazonaws.com", "blob.core.windows.net", "dub.sh", "replit.app",
    "fly.dev", "railway.app", "deno.dev", "web.app", "duckdns.org", "ngrok.io",
    "loca.lt", "trycloudflare.com", "tinyurl.com", "bit.ly", "t.co", "is.gd",
    "cutt.ly", "shorturl.at", "ow.ly", "goo.gl", "buff.ly", "rebrand.ly",
    "supabase.co", "appspot.com", "azurewebsites.net", "cloudfront.net"
}

def extract_apex(url: str) -> str:
    try:
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower().strip()
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
    except Exception:
        return url

def query_rdap(domain: str, timeout: float = 3.0) -> Tuple[Optional[str], Optional[float], str]:
    """Queries RDAP for domain registration date and age in days.
    
    Returns:
        (iso_registration_date, age_days, status_string)
    """
    try:
        url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"Accept": "application/rdap+json", "User-Agent": "PhishGuard-CohortCollector/1.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration":
                    dt_str = ev.get("eventDate", "")
                    if dt_str:
                        dt_clean = dt_str.replace("Z", "+00:00")[:19]
                        dt_reg = datetime.datetime.fromisoformat(dt_clean).replace(tzinfo=datetime.timezone.utc)
                        now = datetime.datetime.now(datetime.timezone.utc)
                        age_days = round(max(0.0, (now - dt_reg).total_seconds() / 86400.0), 1)
                        return dt_clean, age_days, "success"
            return None, None, "no_registration_event"
        elif resp.status_code == 429:
            return None, None, "http_429_rate_limit"
        elif resp.status_code == 404:
            return None, None, "http_404_not_found"
        else:
            return None, None, f"http_{resp.status_code}"
    except requests.exceptions.Timeout:
        return None, None, "timeout"
    except Exception as e:
        return None, None, f"error_{type(e).__name__}"

print("=" * 80)
print("PHISHGUARD AI: TARGETED YOUNG-DOMAIN DATASET COLLECTION")
print("=" * 80)

# -----------------------------------------------------------------------------
# 1. CANDIDATE CURATION FOR COHORT A (LEGITIMATE YOUNG / RECENT STARTUPS & TOOLS)
# -----------------------------------------------------------------------------
# Curating a diverse, verified list of legitimate products, modern tools,
# recently launched open-source projects, modern SaaS, and tech startups.
CANDIDATE_LEGITIMATE_TARGETS = [
    # Modern Developer Tools & Startups (2022-2026 Launches)
    {"url": "https://v0.dev", "domain": "v0.dev", "purpose": "Vercel AI UI generator tool launch", "source": "Vercel Launch"},
    {"url": "https://biomejs.dev", "domain": "biomejs.dev", "purpose": "Modern fast web linter and formatter", "source": "Open Source Launch"},
    {"url": "https://ast-grep.github.io", "domain": "ast-grep.github.io", "purpose": "Structural code search engine", "source": "Developer Tool"},
    {"url": "https://val.town", "domain": "val.town", "purpose": "Social website for writing and running code in the cloud", "source": "Startup Launch"},
    {"url": "https://trigger.dev", "domain": "trigger.dev", "purpose": "Open-source background jobs framework for Next.js", "source": "YC Startup"},
    {"url": "https://inkeep.com", "domain": "inkeep.com", "purpose": "AI search and support agent for developer docs", "source": "YC Startup"},
    {"url": "https://fal.ai", "domain": "fal.ai", "purpose": "Generative media serverless inference platform", "source": "AI Startup"},
    {"url": "https://together.ai", "domain": "together.ai", "purpose": "Cloud platform for training and running open source AI", "source": "AI Startup"},
    {"url": "https://groq.com", "domain": "groq.com", "purpose": "LPU inference engine hardware company", "source": "Tech Company"},
    {"url": "https://mintlify.com", "domain": "mintlify.com", "purpose": "Modern documentation platform for developers", "source": "YC Startup"},
    {"url": "https://dust.tt", "domain": "dust.tt", "purpose": "Custom AI assistants connected to company data", "source": "EU Startup"},
    {"url": "https://midjourney.com", "domain": "midjourney.com", "purpose": "Generative AI imagery tool", "source": "AI Studio"},
    {"url": "https://cursor.com", "domain": "cursor.com", "purpose": "AI-first code editor and IDE", "source": "Anysphere Launch"},
    {"url": "https://cal.com", "domain": "cal.com", "purpose": "Open-source scheduling platform", "source": "Open Core SaaS"},
    {"url": "https://linear.app", "domain": "linear.app", "purpose": "Modern project and issue tracker for high-performance teams", "source": "SaaS Platform"},
    {"url": "https://resend.com", "domain": "resend.com", "purpose": "Email delivery service for developers", "source": "Developer SaaS"},
    {"url": "https://dub.co", "domain": "dub.co", "purpose": "Modern open-source link management infrastructure", "source": "SaaS Platform"},
    {"url": "https://supaglue.com", "domain": "supaglue.com", "purpose": "Open source developer platform for user-facing integrations", "source": "YC Startup"},
    {"url": "https://outerbase.com", "domain": "outerbase.com", "purpose": "AI-powered modern database interface", "source": "SaaS Launch"},
    {"url": "https://convex.dev", "domain": "convex.dev", "purpose": "Reactive backend-as-a-service for web development", "source": "Developer Platform"},
    {"url": "https://trieve.ai", "domain": "trieve.ai", "purpose": "Search and RAG infrastructure for developers", "source": "YC Startup"},
    {"url": "https://speakeasy.com", "domain": "speakeasy.com", "purpose": "API SDK generation and management platform", "source": "Developer Tool"},
    {"url": "https://zeno.build", "domain": "zeno.build", "purpose": "AI evaluation and data debugging toolkit", "source": "Open Source AI"},
    {"url": "https://promptfoo.dev", "domain": "promptfoo.dev", "purpose": "CLI and library for evaluating LLM prompt quality", "source": "Developer Security Tool"},
    {"url": "https://langfuse.com", "domain": "langfuse.com", "purpose": "Open-source LLM observability and evaluation platform", "source": "YC Startup"}
]

print(f"\n[1/2] PROBING COHORT A: LEGITIMATE YOUNG DOMAINS ({len(CANDIDATE_LEGITIMATE_TARGETS)} Candidates)")
cohort_a_records = []
rdap_a_attempts = 0
rdap_a_successes = 0

for item in CANDIDATE_LEGITIMATE_TARGETS:
    u = item["url"]
    d = item["domain"]
    rdap_a_attempts += 1
    
    reg_date, age_days, status = query_rdap(d, timeout=3.0)
    time.sleep(0.15) # Gentle pacing to prevent rate limits
    
    if status == "success" and age_days is not None:
        rdap_a_successes += 1
        cohort_a_records.append({
            "url": u,
            "apex_domain": d,
            "rdap_registration_date": reg_date,
            "registration_age_days": age_days,
            "purpose_note": item["purpose"],
            "source": item["source"],
            "verification_status": "verified_legitimate"
        })
        print(f"  [OK] {d:<24} | Age: {age_days:>7.1f} days | Reg: {reg_date[:10]} | {item['purpose'][:35]}")
    else:
        print(f"  [SKIP] {d:<22} | Status: {status}")

df_cohort_a = pd.DataFrame(cohort_a_records)
df_cohort_a.to_csv(COHORT_A_CSV, index=False)
print(f"--> Saved Cohort A to {COHORT_A_CSV} ({len(df_cohort_a)} verified records)")

# -----------------------------------------------------------------------------
# 2. CANDIDATE CURATION FOR COHORT B (PHISHING YOUNG STANDALONE DOMAINS)
# -----------------------------------------------------------------------------
print(f"\n[2/2] PROBING COHORT B: PHISHING YOUNG STANDALONE DOMAINS FROM FEEDS")
cohort_b_records = []
rdap_b_attempts = 0
rdap_b_successes = 0

if RAW_PHISHING_CSV.exists():
    df_raw_phish = pd.read_csv(RAW_PHISHING_CSV)
    print(f"  - Loaded {len(df_raw_phish)} raw phishing entries from {RAW_PHISHING_CSV.name}")
    
    # Filter for standalone domains (not in PAAS_AND_SHARED_DOMAINS)
    df_raw_phish["apex"] = df_raw_phish["url"].apply(extract_apex)
    standalone_phish = df_raw_phish[~df_raw_phish["apex"].isin(PAAS_AND_SHARED_DOMAINS)].copy()
    # Deduplicate by apex domain to ensure diversity
    standalone_unique = standalone_phish.drop_duplicates(subset=["apex"]).copy()
    print(f"  - Standalone Unique Apex Phishing Candidates: {len(standalone_unique)}")
    
    # Sample candidate standalone phishing domains across .com, .top, .xyz, .site, .vip, .live, .app
    # Test top candidates for RDAP resolution
    candidates_to_probe = standalone_unique.head(60)
    
    for idx, row in candidates_to_probe.iterrows():
        u = row["url"]
        apex = row["apex"]
        src = row.get("source", "OpenPhish/PhishTank")
        
        rdap_b_attempts += 1
        reg_date, age_days, status = query_rdap(apex, timeout=2.5)
        time.sleep(0.15)
        
        if status == "success" and age_days is not None:
            rdap_b_successes += 1
            # Infer lure type from URL heuristics
            lure_type = "generic_credential_lure"
            u_lower = u.lower()
            if any(k in u_lower for k in ["paypal", "wallet", "crypto", "trust", "metamask", "binance", "coinbase"]):
                lure_type = "crypto_or_financial_theft"
            elif any(k in u_lower for k in ["login", "signin", "sso", "auth", "verify", "account", "security"]):
                lure_type = "sso_account_harvesting"
            elif any(k in u_lower for k in ["roblox", "game", "steam", "netflix"]):
                lure_type = "gaming_or_entertainment_lure"
            elif any(k in u_lower for k in ["tax", "refund", "gov", "irs", "post", "parcel", "delivery"]):
                lure_type = "tax_or_delivery_spoof"
                
            cohort_b_records.append({
                "url": u,
                "apex_domain": apex,
                "rdap_registration_date": reg_date,
                "registration_age_days": age_days,
                "source_feed": src,
                "phishing_lure_type": lure_type,
                "verification_status": "verified_phishing_standalone"
            })
            print(f"  [OK] {apex:<32} | Age: {age_days:>7.1f} days | Reg: {reg_date[:10]} | Lure: {lure_type}")
            if len(cohort_b_records) >= 25:
                break
        else:
            print(f"  [SKIP] {apex:<30} | Status: {status}")

df_cohort_b = pd.DataFrame(cohort_b_records)
df_cohort_b.to_csv(COHORT_B_CSV, index=False)
print(f"--> Saved Cohort B to {COHORT_B_CSV} ({len(df_cohort_b)} verified records)")

# -----------------------------------------------------------------------------
# 3. COLLECTION SUMMARY & DATA QUALITY METRICS
# -----------------------------------------------------------------------------
print("\n" + "=" * 80)
print("COLLECTION SUMMARY & DATA QUALITY METRICS")
print("=" * 80)
print(f"Cohort A (Legitimate Young Domains):   {len(df_cohort_a)} verified records")
print(f"  - RDAP Queries Attempted:           {rdap_a_attempts}")
print(f"  - RDAP Successful Resolutions:      {rdap_a_successes} ({rdap_a_successes/rdap_a_attempts*100:.1f}%)")
print(f"  - RDAP Failures/Timeouts:           {rdap_a_attempts - rdap_a_successes} ({(rdap_a_attempts - rdap_a_successes)/rdap_a_attempts*100:.1f}%)")
if not df_cohort_a.empty:
    print(f"  - Domain Age Range (Days):          Min={df_cohort_a['registration_age_days'].min():.1f}d | Median={df_cohort_a['registration_age_days'].median():.1f}d | Max={df_cohort_a['registration_age_days'].max():.1f}d")

print(f"\nCohort B (Phishing Young Standalone Domains): {len(df_cohort_b)} verified records")
print(f"  - RDAP Queries Attempted:           {rdap_b_attempts}")
print(f"  - RDAP Successful Resolutions:      {rdap_b_successes} ({rdap_b_successes/rdap_b_attempts*100:.1f}%)")
print(f"  - RDAP Failures/Timeouts:           {rdap_b_attempts - rdap_b_successes} ({(rdap_b_attempts - rdap_b_successes)/rdap_b_attempts*100:.1f}%)")
if not df_cohort_b.empty:
    print(f"  - Domain Age Range (Days):          Min={df_cohort_b['registration_age_days'].min():.1f}d | Median={df_cohort_b['registration_age_days'].median():.1f}d | Max={df_cohort_b['registration_age_days'].max():.1f}d")

print("\n" + "=" * 80)
print("DATA COLLECTION TASK COMPLETE")
print("=" * 80)
