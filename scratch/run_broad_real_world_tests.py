"""Broad Real-World URL Testing Suite (Part A of Stage 13).

Tests 30+ diverse real-world and synthetic URLs across 5 categories against
the live detection engine API (POST /predict).
"""

import json
import time
import requests

API_URL = "http://127.0.0.1:8000/predict"

TEST_CASES = [
    # -------------------------------------------------------------
    # Category 1: Major legitimate sites, varied architecture
    # -------------------------------------------------------------
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://www.amazon.com",
        "expected": "safe / suspicious (low-medium)",
        "is_phish_expected": False,
        "note": "Major E-commerce (Complex DOM)",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://www.bbc.com",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Major News Site (Server-rendered/Hydrated)",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://www.nytimes.com",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Major News Publisher",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://www.usa.gov",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Government .gov portal",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://www.india.gov.in",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Government .gov.in portal",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://www.jpmorganchase.com",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Major Financial Institution Homepage",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://www.bankofamerica.com",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Major Banking Homepage",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://x.com",
        "expected": "safe / suspicious (SPA shell)",
        "is_phish_expected": False,
        "note": "Social Media (Heavy Client-Side React SPA)",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://github.com",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Developer Platform (SSR + Turbo)",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://gitlab.com",
        "expected": "safe / suspicious (SPA)",
        "is_phish_expected": False,
        "note": "Developer Platform (Vue.js SPA)",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://www.mit.edu",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Higher Education (.edu)",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://www.ox.ac.uk",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Higher Education (.ac.uk)",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://ps.bitsathy.ac.in",
        "expected": "suspicious (medium / SPA shell)",
        "is_phish_expected": False,
        "note": "Educational Institution (Vue/React SPA Shell)",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://vercel.com",
        "expected": "safe / suspicious (Next.js)",
        "is_phish_expected": False,
        "note": "Cloud / Deployment Platform (Next.js)",
    },
    {
        "category": "1. Major Legitimate (Varied Architecture)",
        "url": "https://cloud.google.com",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Cloud Computing Platform",
    },

    # -------------------------------------------------------------
    # Category 2: Legitimate sites with deep links & query parameters
    # -------------------------------------------------------------
    {
        "category": "2. Legitimate Deep Links & Query Params",
        "url": "https://docs.python.org/3/library/urllib.parse.html",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Deep Documentation Path",
    },
    {
        "category": "2. Legitimate Deep Links & Query Params",
        "url": "https://en.wikipedia.org/wiki/Phishing?action=history&offset=20260101",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Deep Query + Keyword in Path",
    },
    {
        "category": "2. Legitimate Deep Links & Query Params",
        "url": "https://github.com/login",
        "expected": "safe (low / login form)",
        "is_phish_expected": False,
        "note": "Legitimate Login Page (Password Form on Real Domain)",
    },
    {
        "category": "2. Legitimate Deep Links & Query Params",
        "url": "https://stackoverflow.com/questions/tagged/python?tab=Votes",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Q&A Forum Deep Query String",
    },
    {
        "category": "2. Legitimate Deep Links & Query Params",
        "url": "https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7095405/",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Scientific Research Deep Link",
    },

    # -------------------------------------------------------------
    # Category 3: Known-safe URLs with structural quirks
    # -------------------------------------------------------------
    {
        "category": "3. Safe URLs with Structural Quirks",
        "url": "https://tinyurl.com/app",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "URL Shortener Domain Homepage",
    },
    {
        "category": "3. Safe URLs with Structural Quirks",
        "url": "https://news.ycombinator.com",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Hacker News (Minimalist Pure Static HTML)",
    },
    {
        "category": "3. Safe URLs with Structural Quirks",
        "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "MDN Web Docs Subdomain + Deep Path",
    },
    {
        "category": "3. Safe URLs with Structural Quirks",
        "url": "https://dev.to",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Developer Community (.to ccTLD)",
    },
    {
        "category": "3. Safe URLs with Structural Quirks",
        "url": "https://raw.githubusercontent.com",
        "expected": "safe (low / degraded)",
        "is_phish_expected": False,
        "note": "Multi-part Subdomain CDN",
    },
    {
        "category": "3. Safe URLs with Structural Quirks",
        "url": "https://about.gitlab.com",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Company Subdomain Portal",
    },

    # -------------------------------------------------------------
    # Category 4: Synthetic / constructed phishing-pattern URLs
    # -------------------------------------------------------------
    {
        "category": "4. Synthetic Phishing Attack Patterns",
        "url": "http://192.168.1.100/paypal/login.php",
        "expected": "phishing (high)",
        "is_phish_expected": True,
        "note": "Raw IPv4 + Brand Path + Insecure HTTP",
    },
    {
        "category": "4. Synthetic Phishing Attack Patterns",
        "url": "http://10.0.0.1/secure-banking/verification.html",
        "expected": "phishing (high)",
        "is_phish_expected": True,
        "note": "Raw Private IP + Credential Verification Path",
    },
    {
        "category": "4. Synthetic Phishing Attack Patterns",
        "url": "http://paypal-account-verification.security-update.xyz/login.php",
        "expected": "phishing (high)",
        "is_phish_expected": True,
        "note": "Brand Impersonation Subdomain + Suspicious TLD (.xyz)",
    },
    {
        "category": "4. Synthetic Phishing Attack Patterns",
        "url": "http://wellsfargo.com.security-alert-service.top/auth/signin.html",
        "expected": "phishing (high)",
        "is_phish_expected": True,
        "note": "Brand Subdomain Deception + .top TLD + Auth Path",
    },
    {
        "category": "4. Synthetic Phishing Attack Patterns",
        "url": "http://chase-bank-verify-identity.support-desk.account-update.tk/index.html",
        "expected": "phishing (high)",
        "is_phish_expected": True,
        "note": "Excessive Subdomains + Sensitive Keywords + .tk TLD",
    },
    {
        "category": "4. Synthetic Phishing Attack Patterns",
        "url": "http://172.16.254.1:8080/apple/id/account/billing/signin",
        "expected": "phishing (high)",
        "is_phish_expected": True,
        "note": "Raw IP + Non-standard Port + Brand Spoofing Deep Path",
    },

    # -------------------------------------------------------------
    # Category 5: Edge-case inputs
    # -------------------------------------------------------------
    {
        "category": "5. Edge-Case URL Inputs",
        "url": "https://example.com/search?q=cybersecurity&category=research&filter=recent#top-results",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Complex Query Parameters + Fragment (#)",
    },
    {
        "category": "5. Edge-Case URL Inputs",
        "url": "https://example.com/path_with-dashes.and_underscores~and.dots/test",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Valid URL Special Characters (~, -, _, .)",
    },
    {
        "category": "5. Edge-Case URL Inputs",
        "url": "https://example.com/" + ("subfolder/" * 15) + "document.html",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "Very Deep Legitimate Path (~160 chars)",
    },
    {
        "category": "5. Edge-Case URL Inputs",
        "url": "https://xn--e1afmkfd.xn--p1ai",
        "expected": "safe / suspicious",
        "is_phish_expected": False,
        "note": "Punycode Internationalized Domain Name (IDN)",
    },
    {
        "category": "5. Edge-Case URL Inputs",
        "url": "https://example.com/?redirect=https%3A%2F%2Fother.com%2Fpath%3Fparam%3Dval",
        "expected": "safe (low)",
        "is_phish_expected": False,
        "note": "URL-Encoded Query Parameter Containing Nested URL",
    },
]

def run_tests():
    print("=" * 80)
    print(f"RUNNING BROAD REAL-WORLD URL TEST BATTERY ({len(TEST_CASES)} URLs)")
    print("=" * 80)

    results = []
    
    for idx, tc in enumerate(TEST_CASES, 1):
        url = tc["url"]
        cat = tc["category"]
        expected = tc["expected"]
        is_phish_exp = tc["is_phish_expected"]
        note = tc["note"]

        print(f"\n[{idx}/{len(TEST_CASES)}] {cat}")
        print(f"  Target URL: {url[:70]}{'...' if len(url) > 70 else ''}")
        print(f"  Note: {note}")

        t0 = time.perf_counter()
        try:
            resp = requests.post(API_URL, json={"url": url}, timeout=18)
            duration_ms = (time.perf_counter() - t0) * 1000.0
            
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status")
                risk_level = data.get("risk_level")
                confidence = data.get("confidence", 0.0)
                is_phishing = data.get("is_phishing", False)
                html_avail = data.get("html_available", False)
                spa_incomplete = data.get("content_rendering_incomplete", False)
                indicators = data.get("detected_indicators", [])

                # Match evaluation:
                # - For legitimate targets: match if is_phishing is False and risk_level is in ['low', 'medium']
                # - For phishing targets: match if is_phishing is True and risk_level == 'high'
                if is_phish_exp:
                    match = (is_phishing is True) and (risk_level == "high" or status == "phishing")
                else:
                    match = (is_phishing is False) and (risk_level in ("low", "medium"))

                res_entry = {
                    "index": idx,
                    "category": cat,
                    "url": url,
                    "note": note,
                    "expected": expected,
                    "actual_status": status,
                    "actual_risk": risk_level,
                    "actual_confidence": confidence,
                    "is_phishing": is_phishing,
                    "html_available": html_avail,
                    "content_rendering_incomplete": spa_incomplete,
                    "match": match,
                    "duration_ms": duration_ms,
                    "indicators_count": len(indicators),
                    "indicators": indicators,
                }
                results.append(res_entry)

                status_str = f"Status: {status.upper()} | Risk: {risk_level.upper()} | Conf: {confidence*100:.1f}%"
                match_str = "[MATCH]" if match else "[MISMATCH]"
                print(f"  Response ({duration_ms:.0f}ms): {status_str} -> {match_str}")
                if spa_incomplete:
                    print(f"  [SPA Shell Detected]: {spa_incomplete}")
                if not html_avail:
                    print(f"  [Degraded Mode]: HTML unavailable")
                if not match:
                    print(f"  [INVESTIGATION NEEDED]: Expected {expected}, got {status_str}")
                    print(f"  Indicators: {indicators}")
            else:
                print(f"  HTTP ERROR {resp.status_code}: {resp.text}")
                results.append({
                    "index": idx,
                    "category": cat,
                    "url": url,
                    "note": note,
                    "expected": expected,
                    "actual_status": f"HTTP_{resp.status_code}",
                    "actual_risk": "error",
                    "actual_confidence": 0.0,
                    "is_phishing": False,
                    "match": False,
                    "duration_ms": duration_ms,
                    "indicators": [],
                })
        except Exception as exc:
            print(f"  EXCEPTION: {exc}")
            results.append({
                "index": idx,
                "category": cat,
                "url": url,
                "note": note,
                "expected": expected,
                "actual_status": "EXCEPTION",
                "actual_risk": "error",
                "actual_confidence": 0.0,
                "is_phishing": False,
                "match": False,
                "duration_ms": 0.0,
                "indicators": [str(exc)],
            })

    # Save summary to JSON
    with open("scratch/broad_url_test_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 80)
    print("SUMMARY OF BROAD REAL-WORLD URL TESTING")
    print("=" * 80)
    total = len(results)
    matches = sum(1 for r in results if r["match"])
    mismatches = total - matches
    print(f"Total URLs Tested: {total}")
    print(f"Matches:           {matches} ({matches/total*100:.1f}%)")
    print(f"Mismatches:        {mismatches} ({mismatches/total*100:.1f}%)")

if __name__ == "__main__":
    run_tests()
