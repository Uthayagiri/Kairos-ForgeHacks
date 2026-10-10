"""Registration-Date-First Sourcing for Cohort A (Legitimate Young Domains < 14 Days Old).

Multi-Source Ingestion:
1. CT Logs via ctlogs.dev across diverse TLDs and non-PaaS apex domain patterns.
2. Urlscan.io recent live scans (filtered for non-malicious categories: portfolio, studio, cafe, local business, tech, indie).
3. Targeted domain queries across student projects, events, local businesses, pre-launch indie projects, and open source tools.

Strict Filtering:
- RDAP confirmation: Domain registration date MUST be < 14.0 days old relative to 2026-09-08 (registered on or after 2026-08-25).
- Live Content Fetch & Legitimacy Heuristics:
  * Exclude parked/for-sale placeholders (GoDaddy, Sedo, Dan, Bodis, Namecheap parking, etc.)
  * Exclude generic default server pages (nginx default, apache default, IIS)
  * Exclude brand spoofing, crypto/financial lures, and suspicious spam
  * Verify coherent, non-spoofed, genuine project/business/personal content
  * Exclude anything ambiguous.
"""

import datetime
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import pandas as pd
import requests

NOW = datetime.datetime(2026, 9, 8, 15, 40, 0, tzinfo=datetime.timezone.utc)
CUTOFF_DATE = datetime.datetime(2026, 8, 25, 0, 0, 0, tzinfo=datetime.timezone.utc)

REPO_ROOT = Path("c:/Users/Udhaya/S5_Phishing_Detector").resolve()
BACKEND_DIR = REPO_ROOT / "backend"
COHORT_DIR = BACKEND_DIR / "data" / "young_domain_cohort"
COHORT_DIR.mkdir(parents=True, exist_ok=True)
COHORT_A_CSV = COHORT_DIR / "cohort_a_legitimate_young_domains.csv"
EXCLUSION_LOG_PATH = COHORT_DIR / "cohort_a_exclusions.log"

PAAS_DOMAINS = {
    "pages.dev", "netlify.app", "github.io", "vercel.app", "firebaseapp.com",
    "render.com", "glitch.me", "surge.sh", "blogspot.com", "wordpress.com",
    "wixsite.com", "weebly.com", "000webhostapp.com", "sites.google.com",
    "s3.amazonaws.com", "blob.core.windows.net", "dub.sh", "replit.app",
    "fly.dev", "railway.app", "deno.dev", "web.app", "duckdns.org", "ngrok.io",
    "loca.lt", "trycloudflare.com", "tinyurl.com", "bit.ly", "t.co", "myshopify.com"
}

PARKING_INDICATORS = [
    "buy this domain", "domain for sale", "parked free", "godaddy", "sedoparking",
    "dan.com", "namecheap parking", "hugedomains", "inquire about this domain",
    "domain has been registered", "under construction", "coming soon placeholder",
    "renew your domain", "parked domain", "bodis.com", "this domain is registered",
    "afternic.com", "domainname.com", "domainmarket", "porkbun parking",
    "welcome to openresty", "apache2 ubuntu default page", "welcome to nginx",
    "iis windows server", "hostinger default page", "cpanel default",
    "this site is under development", "domain is parked", "parked on",
    "domain parking", "search ads", "related links", "inquire now"
]

PHISH_INDICATORS = [
    "paypal", "chase", "wellsfargo", "bankofamerica", "metamask", "binance",
    "trustwallet", "coinbase", "appleid", "icloud-verify", "netflix-billing",
    "steam-community", "roblox-redeem", "security-alert", "irs-tax", "usps-tracking",
    "account suspended", "verify your account", "urgent security update", "wallet connect"
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
        "com.au", "net.au", "co.jp", "com.br", "co.za", "com.ph", "com.tw"
    }
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in two_part_tlds and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}"
    return f"{parts[-2]}.{parts[-1]}"

def query_rdap(domain: str, timeout: float = 3.5) -> Tuple[Optional[str], Optional[float], str]:
    """Queries RDAP for domain registration date and computes age in days."""
    try:
        url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"Accept": "application/rdap+json", "User-Agent": "PhishGuard-CohortA-Collector/2.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            for ev in data.get("events", []):
                if ev.get("eventAction") in ("registration", "registered"):
                    dt_str = ev.get("eventDate", "")
                    if dt_str:
                        dt_clean = dt_str.replace("Z", "+00:00")[:19]
                        dt_reg = datetime.datetime.fromisoformat(dt_clean).replace(tzinfo=datetime.timezone.utc)
                        age_days = round(max(0.0, (NOW - dt_reg).total_seconds() / 86400.0), 1)
                        return dt_clean, age_days, "success"
            return None, None, "no_registration_event_in_rdap"
        elif resp.status_code == 404:
            return None, None, "rdap_404_not_found"
        elif resp.status_code == 429:
            return None, None, "rdap_429_rate_limited"
        else:
            return None, None, f"rdap_http_{resp.status_code}"
    except requests.exceptions.Timeout:
        return None, None, "rdap_timeout"
    except Exception as e:
        return None, None, f"rdap_error_{type(e).__name__}"

def check_legitimacy_detailed(url: str, timeout: float = 4.0) -> Tuple[bool, str, Optional[str], Optional[str]]:
    """Inspects live HTTP response and HTML to verify legitimacy.
    
    Returns:
        (is_legit, rejection_or_acceptance_reason, title, site_category)
    """
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        if resp.status_code not in (200, 301, 302, 307, 308):
            return False, f"unreachable_http_status_{resp.status_code}", None, None
            
        text_lower = resp.text.lower()
        
        # 1. Check parking / domain broker / placeholder
        for pk in PARKING_INDICATORS:
            if pk in text_lower:
                return False, f"parked_domain_or_placeholder ({pk})", None, None
                
        # 2. Check phishing / brand theft / credential harvest indicators
        for ph in PHISH_INDICATORS:
            if ph in text_lower:
                return False, f"suspicious_phishing_or_credential_lure ({ph})", None, None
                
        # 3. Check minimum substantive content
        if len(resp.text.strip()) < 200:
            return False, "insufficient_content_empty_or_stub_page", None, None
            
        # 4. Extract Title
        m_title = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        title_str = m_title.group(1).strip() if m_title else "Untitled Page"
        title_clean = re.sub(r"\s+", " ", title_str)[:70]
        
        # 5. Check if title looks like a parked / error / default page
        title_lower = title_clean.lower()
        if any(w in title_lower for w in ["404", "not found", "error", "domain for sale", "parked", "buy this", "cpanel", "apache2"]):
            return False, f"parked_or_error_title ({title_clean})", None, None
            
        # 6. Categorize site
        category = "Independent Web Project / Business"
        if any(k in text_lower for k in ["portfolio", "about me", "resume", "developer", "designer", "engineer", "projects"]):
            category = "Personal Developer Portfolio / Blog"
        elif any(k in text_lower for k in ["menu", "order", "restaurant", "cafe", "services", "contact us", "hours", "locations", "clinic", "law", "cleaning"]):
            category = "Local Business / Service"
        elif any(k in text_lower for k in ["hackathon", "symposium", "conference", "event", "schedule", "speakers", "register"]):
            category = "Event / Hackathon / Community"
        elif any(k in text_lower for k in ["open source", "docs", "documentation", "github", "api", "sdk", "cli", "library"]):
            category = "Open Source / Developer Tooling"
        elif any(k in text_lower for k in ["club", "student", "society", "chapter", "nonprofit", "foundation", "charity"]):
            category = "Student Club / Small Nonprofit"
        elif any(k in text_lower for k in ["features", "pricing", "sign up", "waitlist", "pre-launch", "coming soon", "launching in"]):
            category = "Pre-Launch Product / Startup Landing Page"
            
        return True, "verified_legitimate_coherent_content", title_clean, category
        
    except requests.exceptions.SSLError:
        return False, "ssl_handshake_or_certificate_error", None, None
    except requests.exceptions.ConnectionError:
        return False, "connection_refused_or_dns_nxdomain", None, None
    except requests.exceptions.Timeout:
        return False, "http_connection_timeout", None, None
    except Exception as e:
        return False, f"fetch_exception_{type(e).__name__}", None, None

def collect_candidates_from_ctlogs() -> Set[str]:
    """Queries ctlogs.dev across diverse search patterns."""
    patterns = [
        "studio", "design", "tech", "dev", "space", "club", "events", "photography",
        "consulting", "agency", "solutions", "digital", "cafe", "store", "online",
        "portfolio", "academy", "creative", "media", "craft", "works", "group", "ventures"
    ]
    tlds = ["dev", "design", "studio", "space", "tech", "io", "me", "club", "events", "agency", "digital", "app", "site", "online", "co", "cc"]
    
    candidates = set()
    print("[1/3] Sourcing from Certificate Transparency Logs (ctlogs.dev)...", flush=True)
    
    for tld in tlds:
        for p in patterns[:6]:
            query = f"{p}.{tld}"
            url = f"https://ctlogs.dev/search?q={query}&output=json"
            try:
                resp = requests.get(url, timeout=3.5, headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    rows = data.get("rows", [])
                    for row in rows:
                        match_dom = row.get("match", "")
                        not_before = row.get("not_before", "")
                        if match_dom and not_before:
                            try:
                                dt_cert = datetime.datetime.fromisoformat(not_before.replace("Z", "+00:00"))
                                if dt_cert >= CUTOFF_DATE:
                                    apex = extract_apex(match_dom)
                                    if apex not in PAAS_DOMAINS and "." in apex and len(apex) > 4:
                                        candidates.add(apex)
                            except Exception:
                                pass
                time.sleep(0.08)
            except Exception:
                pass
        print(f"  Processed .{tld} patterns -> Current unique candidates: {len(candidates)}", flush=True)
        
    return candidates

def collect_candidates_from_urlscan() -> Set[str]:
    """Queries urlscan.io for recent live scans."""
    candidates = set()
    print("\n[2/3] Sourcing from Urlscan.io Live Scans (task.time:>2026-08-25)...", flush=True)
    
    queries = [
        'task.time:>2026-08-25 AND (page.domain:*.design OR page.domain:*.studio OR page.domain:*.tech OR page.domain:*.dev OR page.domain:*.space OR page.domain:*.me)',
        'task.time:>2026-08-25 AND NOT page.domain:*.ph AND NOT page.domain:*.xyz AND (page.title:portfolio OR page.title:studio OR page.title:consulting OR page.title:cafe OR page.title:event)',
        'task.time:>2026-08-25 AND page.status:200'
    ]
    
    for q in queries:
        try:
            url = f"https://urlscan.io/api/v1/search/?q={requests.utils.quote(q)}&size=100"
            resp = requests.get(url, timeout=6.0, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                data = resp.json()
                results = data.get("results", [])
                for r in results:
                    page = r.get("page", {})
                    dom = page.get("apexDomain") or page.get("domain", "")
                    if dom:
                        apex = extract_apex(dom)
                        if apex not in PAAS_DOMAINS and "." in apex and len(apex) > 4:
                            candidates.add(apex)
            print(f"  Urlscan query yielded -> Total unique candidates: {len(candidates)}", flush=True)
            time.sleep(0.3)
        except Exception as e:
            print(f"  Urlscan query error: {e}", flush=True)
            
    return candidates

def collect_niche_seed_domains() -> Set[str]:
    """Seed non-PaaS candidates from recent developer communities, hackathons, indie projects, and student organizations."""
    print("\n[3/3] Sourcing from Niche Developer, Indie Project, and Community Registry Seeds...", flush=True)
    seeds = [
        "ysimulator.run", "flowripple.com", "seeking-maintainers.net", "http-response.com",
        "lablab.ai", "reskilll.com", "knowafest.com", "unstop.com", "promptfoo.dev",
        "langfuse.com", "v0.dev", "biomejs.dev", "val.town", "trigger.dev", "mintlify.com",
        "convex.dev", "shadcn.com", "trieve.ai", "tldraw.dev", "cal.com", "dub.co",
        "openstatus.dev", "better-auth.com", "polar.sh", "papermark.io", "midday.ai",
        "twenty.com", "formbricks.com", "documenso.com", "typebot.io", "infisical.com"
    ]
    return set(seeds)

def main():
    print("=" * 90, flush=True)
    print("RE-ATTEMPTING COHORT A: REGISTRATION-DATE-FIRST SOURCING PIPELINE", flush=True)
    print(f"Current Date: {NOW.isoformat()} | Cutoff Date: {CUTOFF_DATE.isoformat()} (<14.0 days)", flush=True)
    print("=" * 90, flush=True)
    
    # 1. Ingest Candidates
    ct_candidates = collect_candidates_from_ctlogs()
    urlscan_candidates = collect_candidates_from_urlscan()
    seed_candidates = collect_niche_seed_domains()
    
    all_candidates = sorted(list(ct_candidates | urlscan_candidates | seed_candidates))
    print(f"\nTotal Unique Candidate Domains to Process: {len(all_candidates)}", flush=True)
    
    # 2. RDAP & Legitimacy Audit
    print("\n" + "=" * 90, flush=True)
    print("BEGINNING INDEPENDENT RDAP RESOLUTION & LIVE LEGITIMACY REVIEW", flush=True)
    print("=" * 90, flush=True)
    
    verified_cohort_a = []
    exclusions = []
    
    total_probed = 0
    rdap_success_count = 0
    rdap_failure_count = 0
    age_under_14_count = 0
    age_over_14_count = 0
    
    for idx, domain in enumerate(all_candidates, 1):
        total_probed += 1
        reg_date, age_days, rdap_status = query_rdap(domain, timeout=3.0)
        time.sleep(0.10) # respectful rate limit
        
        if rdap_status == "success" and age_days is not None:
            rdap_success_count += 1
            
            if age_days < 14.0:
                age_under_14_count += 1
                # Domain is genuinely < 14 days old! Now verify live content & legitimacy
                url = f"https://{domain}"
                is_legit, reason, title, category = check_legitimacy_detailed(url, timeout=3.5)
                
                if not is_legit and "ssl" in reason:
                    # Try http fallback
                    url_http = f"http://{domain}"
                    is_legit, reason, title, category = check_legitimacy_detailed(url_http, timeout=3.5)
                    if is_legit:
                        url = url_http
                        
                if is_legit:
                    record = {
                        "url": url,
                        "apex_domain": domain,
                        "rdap_registration_date": reg_date,
                        "registration_age_days": age_days,
                        "purpose_note": f"{category} | {title}",
                        "source": "Registration-Date-First (CT/Urlscan + RDAP)",
                        "verification_status": "verified_legitimate_young_domain"
                    }
                    verified_cohort_a.append(record)
                    print(f"  [QUALIFIED COHORT A] #{len(verified_cohort_a)}: {domain:<26} | Age: {age_days:>4.1f}d | {category} | {title[:30]}", flush=True)
                else:
                    exclusions.append({
                        "domain": domain,
                        "rdap_age_days": age_days,
                        "registration_date": reg_date,
                        "exclusion_stage": "legitimacy_content_audit",
                        "exclusion_reason": reason
                    })
                    print(f"  [EXCLUDED - CONTENT]  {domain:<26} | Age: {age_days:>4.1f}d | Reason: {reason}", flush=True)
            else:
                age_over_14_count += 1
                exclusions.append({
                    "domain": domain,
                    "rdap_age_days": age_days,
                    "registration_date": reg_date,
                    "exclusion_stage": "rdap_age_check",
                    "exclusion_reason": f"age_ge_14_days ({age_days:.1f} days old; registered {reg_date[:10]})"
                })
        else:
            rdap_failure_count += 1
            exclusions.append({
                "domain": domain,
                "rdap_age_days": None,
                "registration_date": None,
                "exclusion_stage": "rdap_lookup",
                "exclusion_reason": f"rdap_{rdap_status}"
            })
            
        if idx % 25 == 0 or idx == len(all_candidates):
            print(f"  ... Progress: {idx}/{len(all_candidates)} probed | RDAP OK: {rdap_success_count} | <14d: {age_under_14_count} | Verified: {len(verified_cohort_a)}", flush=True)
            
    # 3. Save Results
    df_out = pd.DataFrame(verified_cohort_a)
    df_out.to_csv(COHORT_A_CSV, index=False)
    
    with open(EXCLUSION_LOG_PATH, "w", encoding="utf-8") as f:
        for exc in exclusions:
            f.write(json.dumps(exc) + "\n")
            
    # 4. Final Comprehensive Reporting
    print("\n" + "=" * 90, flush=True)
    print("COHORT A REGISTRATION-DATE-FIRST HARVESTING REPORT", flush=True)
    print("=" * 90, flush=True)
    print(f"Total Domains Probed:                 {total_probed}", flush=True)
    print(f"RDAP Lookups Succeeded:               {rdap_success_count} ({rdap_success_count / max(1, total_probed) * 100:.1f}%)", flush=True)
    print(f"RDAP Lookups Failed/Timeout:          {rdap_failure_count} ({rdap_failure_count / max(1, total_probed) * 100:.1f}%)", flush=True)
    print(f"Domains with RDAP Age < 14.0 Days:    {age_under_14_count}", flush=True)
    print(f"Domains with RDAP Age >= 14.0 Days:   {age_over_14_count}", flush=True)
    print(f"Candidates Excluded for Ambiguity:    {len([e for e in exclusions if e['exclusion_stage'] == 'legitimacy_content_audit'])}", flush=True)
    print(f"Final Verified Qualifying Cohort A:   {len(verified_cohort_a)} records", flush=True)
    print(f"Output Saved To:                      {COHORT_A_CSV}", flush=True)
    print(f"Exclusion Log Saved To:               {EXCLUSION_LOG_PATH}", flush=True)
    print("=" * 90, flush=True)

if __name__ == "__main__":
    main()
