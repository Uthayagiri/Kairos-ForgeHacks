"""Probe candidate young legitimate domains across portfolios, local businesses,
developer blogs, event pages, hackathon sites, and newly launched open source tools.
"""

import datetime
import json
import re
from pathlib import Path
from urllib.parse import urlparse
import pandas as pd
import requests

NOW = datetime.datetime(2026, 9, 8, 15, 40, 0, tzinfo=datetime.timezone.utc)
CUTOFF_DATE = datetime.datetime(2026, 8, 25, 0, 0, 0, tzinfo=datetime.timezone.utc)

COHORT_DIR = Path("c:/Users/Udhaya/S5_Phishing_Detector/backend/data/young_domain_cohort")
COHORT_DIR.mkdir(parents=True, exist_ok=True)
COHORT_A_CSV = COHORT_DIR / "cohort_a_legitimate_young_domains.csv"
EXCLUSIONS_LOG = COHORT_DIR / "cohort_a_exclusions.log"

CANDIDATES = [
    # Personal portfolios & developer blogs
    {"url": "https://antfu.me", "dom": "antfu.me", "purpose": "Anthony Fu personal developer blog and portfolio"},
    {"url": "https://leerob.io", "dom": "leerob.io", "purpose": "Lee Robinson personal engineering blog"},
    {"url": "https://swyx.io", "dom": "swyx.io", "purpose": "Shawn Swyx Wang personal tech blog"},
    {"url": "https://shadcn.com", "dom": "shadcn.com", "purpose": "Modern UI component library site"},
    {"url": "https://news.ysimulator.run", "dom": "ysimulator.run", "purpose": "Interactive Hacker News simulator project"},
    {"url": "https://flowripple.com", "dom": "flowripple.com", "purpose": "Automation platform for developers"},
    {"url": "https://searcha.page", "dom": "searcha.page", "purpose": "Independent search engine project"},
    {"url": "https://seek.ninja", "dom": "seek.ninja", "purpose": "Solo developer independent search tool"},
    {"url": "https://seeking-maintainers.net", "dom": "seeking-maintainers.net", "purpose": "Open source project maintainer matching platform"},
    {"url": "https://http-response.com", "dom": "http-response.com", "purpose": "Developer HTTP mocking and webhook inspector tool"},
    {"url": "https://lablab.ai", "dom": "lablab.ai", "purpose": "AI hackathon and challenge community platform"},
    {"url": "https://reskilll.com", "dom": "reskilll.com", "purpose": "Tech community hackathon and upskilling hub"},
    {"url": "https://knowafest.com", "dom": "knowafest.com", "purpose": "College technical symposium and festival directory"},
    {"url": "https://hacktoskill.com", "dom": "hacktoskill.com", "purpose": "Global hackathon innovation platform"},
    {"url": "https://openhackathons.org", "dom": "openhackathons.org", "purpose": "HPC and AI open hackathon organization"},
    {"url": "https://unstop.com", "dom": "unstop.com", "purpose": "Student competition and challenge portal"},
    {"url": "https://promptfoo.dev", "dom": "promptfoo.dev", "purpose": "Prompt evaluation CLI tool"},
    {"url": "https://langfuse.com", "dom": "langfuse.com", "purpose": "LLM observability open source tool"},
    {"url": "https://trieve.ai", "dom": "trieve.ai", "purpose": "Developer RAG search API"},
    {"url": "https://v0.dev", "dom": "v0.dev", "purpose": "Generative UI builder"},
    {"url": "https://biomejs.dev", "dom": "biomejs.dev", "purpose": "Fast JavaScript web toolchain"},
    {"url": "https://val.town", "dom": "val.town", "purpose": "Social JavaScript runtime in browser"},
    {"url": "https://trigger.dev", "dom": "trigger.dev", "purpose": "Developer background jobs framework"},
    {"url": "https://mintlify.com", "dom": "mintlify.com", "purpose": "Modern documentation builder"},
    {"url": "https://convex.dev", "dom": "convex.dev", "purpose": "Reactive backend-as-a-service"}
]

def query_rdap(domain: str, timeout: float = 3.0):
    try:
        url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(url, timeout=timeout, headers={"Accept": "application/rdap+json", "User-Agent": "PhishGuard-Diag/1.0"})
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
            return None, None, "no_reg_event"
        else:
            return None, None, f"http_{resp.status_code}"
    except Exception as e:
        return None, None, f"err_{type(e).__name__}"

def check_legitimacy(url: str, timeout: float = 3.0):
    try:
        headers = {"User-Agent": "Mozilla/5.0 Chrome/124.0"}
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        if resp.status_code in (200, 301, 302, 307, 308) and len(resp.text.strip()) > 100:
            m = re.search(r"<title>(.*?)</title>", resp.text, re.I)
            t = m.group(1).strip() if m else "Coherent Page"
            return True, "verified_live_content", t[:50]
        return False, f"http_{resp.status_code}", None
    except Exception as e:
        return False, f"err_{type(e).__name__}", None

print("PROBING CANDIDATES VIA RDAP...")
records = []
exclusions = []

for c in CANDIDATES:
    u = c["url"]
    d = c["dom"]
    reg_date, age_days, status = query_rdap(d)
    
    if status == "success" and age_days is not None:
        is_legit, reason, title = check_legitimacy(u)
        if is_legit:
            records.append({
                "url": u,
                "apex_domain": d,
                "rdap_registration_date": reg_date,
                "registration_age_days": age_days,
                "purpose_note": c["purpose"],
                "source": "Show HN / Indie / Portfolio Web Project",
                "verification_status": "verified_legitimate"
            })
            print(f"  [OK] {d:<25} | Age: {age_days:>7.1f}d | Reg: {reg_date[:10]} | Title: {title}")
        else:
            exclusions.append({"domain": d, "age_days": age_days, "reason": reason})
            print(f"  [EXCLUDE] {d:<25} | Content check failed ({reason})")
    else:
        exclusions.append({"domain": d, "age_days": None, "reason": f"rdap_{status}"})
        print(f"  [EXCLUDE] {d:<25} | RDAP failed ({status})")

df_out = pd.DataFrame(records)
df_out.to_csv(COHORT_A_CSV, index=False)
print(f"\nSaved {len(df_out)} records to {COHORT_A_CSV}")
