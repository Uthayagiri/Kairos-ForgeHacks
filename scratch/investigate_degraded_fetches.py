"""Deep Dive Investigation: Why Major Legitimate Sites Triggered Degraded Fetch Mode.

Examines the exact network responses, status codes, WAF/CDN headers, and blocking reasons
for Oxford, Google Cloud, Wikipedia deep link, Stack Overflow, and Example.com.
"""

import sys
from pathlib import Path
import requests

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from app.services.detection_engine import DetectionEngine, USER_AGENT

engine = DetectionEngine()

TARGETS = [
    ("Oxford University", "https://www.ox.ac.uk"),
    ("Google Cloud", "https://cloud.google.com"),
    ("Wikipedia Deep Link", "https://en.wikipedia.org/wiki/Phishing?action=history&offset=20260101"),
    ("Stack Overflow Deep Query", "https://stackoverflow.com/questions/tagged/python?tab=Votes"),
    ("Example.com Query Edge", "https://example.com/search?q=cybersecurity&category=research&filter=recent#top-results"),
]

print("=" * 80)
print("DEEP DIVE: INVESTIGATING DEGRADED FETCH REASONS")
print("=" * 80)

for label, url in TARGETS:
    print(f"\n--- [{label}] {url} ---")
    
    # 1. Test via DetectionEngine.fetch_single_html
    ok, content, err_reason, is_ssl = engine.fetch_single_html(url)
    print(f"Engine Fetch Result: success={ok}, error_reason='{err_reason}', is_ssl_error={is_ssl}")
    if content:
        print(f"Content Length: {len(content)} chars")

    # 2. Raw requests call with detailed header inspection
    try:
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        raw_resp = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=True)
        print(f"Raw HTTP Status: {raw_resp.status_code} {raw_resp.reason}")
        print(f"Content-Type: {raw_resp.headers.get('Content-Type')}")
        print(f"Server / CDN: {raw_resp.headers.get('Server')}")
        
        # Check for common WAF / Bot protection headers
        waf_headers = {}
        for h in ["cf-ray", "server", "x-amz-cf-id", "x-cache", "akamai-grn", "x-akamai-transformed", "set-cookie"]:
            if h in raw_resp.headers:
                waf_headers[h] = raw_resp.headers[h][:60] + "..." if len(raw_resp.headers[h]) > 60 else raw_resp.headers[h]
        print(f"Security / CDN Headers: {waf_headers}")
        
        if raw_resp.status_code != 200:
            print(f"Blocking Details: Response snippet: {raw_resp.text[:200]}")
    except Exception as exc:
        print(f"Raw Request Exception: {type(exc).__name__}: {exc}")
