import requests
import json

candidates = [
    ("Legitimate Wikipedia", "https://en.wikipedia.org/wiki/Main_Page"),
    ("Legitimate Python Docs", "https://docs.python.org/3/library/index.html"),
    ("Suspicious Degraded Portal", "https://portal.university.edu/student-login"),
    ("Suspicious Degraded OS Docs", "https://docs.python.org/3/library/os.html"),
    ("Suspicious Unreachable Biz", "http://unverified-fast-news.biz/article/2026"),
    ("High-Risk Phishing Top TLD", "http://paypal-security-update.account-verification.login.top/auth/verify"),
    ("High-Risk Phishing Private IP SSRF", "http://192.168.1.50/secure-login/account-verification"),
    ("High-Risk Phishing Loopback SSRF", "http://127.0.0.1:8000/admin/login"),
    ("High-Risk Phishing Apple Lure", "http://apple-id-verify.security-locked.top/signin")
]

for label, url in candidates:
    try:
        r = requests.post("http://127.0.0.1:8000/api/analyze", json={"url": url}, timeout=10)
        d = r.json()
        print(f"[{label}] {url}")
        print(f"  Status: {d.get('status')} | Risk: {d.get('risk_level')} | Score: {d.get('risk_score')}%")
        print(f"  HTML: {d.get('html_available')} | Action: {d.get('recommended_action')}")
        print(f"  Indicators: {d.get('detected_indicators')[:2]}\n")
    except Exception as e:
        print(f"[{label}] Error: {e}\n")
