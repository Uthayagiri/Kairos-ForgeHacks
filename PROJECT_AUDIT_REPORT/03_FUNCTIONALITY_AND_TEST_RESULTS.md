# PhishGuard AI — Functionality & Empirical Test Results

## 1. Feature-by-Feature Implementation Status

| Feature / Capability | Claimed Status | Verified Status | Evidence & Actual Behavior |
| :--- | :--- | :---: | :--- |
| **URL Lexical Analysis** | 43 Features total (22 URL) | **Implemented & Tested** | `extract_url_features()` parses lengths, subdomains, TLDs, keywords, obfuscation in < 1 ms without unhandled exceptions. |
| **Static HTML Inspection** | Live DOM analysis (21 features) | **Implemented & Tested** | `extract_html_features()` correctly extracts form actions, inputs, password fields, iframes, links, and text ratio from static HTML. |
| **SSRF Perimeter Filter** | Blocks private/loopback IPs | **Partially Working** | `is_safe_ssrf_destination()` blocks initial direct IPs (`127.0.0.1`, `169.254.169.254`), but bypassable via HTTP 302 redirects. |
| **Degraded-Mode Bounding** | Prevents false alarms on unreachability | **Implemented & Tested** | Correctly dampens ML probability to `<= 0.48` when HTML cannot be fetched, unless strong URL threats exist. |
| **SPA Shell Detection** | Identifies React/Vue client apps | **Implemented & Tested** | `is_likely_unrendered_spa_shell()` correctly flags client-rendered shells and bounds score to "Suspicious" (48%). |
| **XGBoost Inference** | Calibrated ML risk scoring | **Implemented & Tested** | Model inference completes in 15–20 ms; output is an ordinal risk score skewed by `scale_pos_weight=5.0`. |
| **Active Navigation Blocking** | Real-time prevention in browser | **Broken / Missing** | Extension contains **no** navigation interception. Phishing sites load freely; warning is purely advisory in a separate tab. |
| **Automatic Tab Monitoring** | Scans URLs as user navigates | **Broken / Missing** | `service-worker.js` does not listen to navigation events. Analysis triggers only upon manual popup opening. |
| **TLS/SSL Certificate Audit** | Verifies HTTPS validity | **Nonexistent** | Backend uses `verify=False` in `requests.get()`. SSL errors are suppressed, and cert chain/age are never checked. |
| **WHOIS / Domain Age** | Checks domain registration age | **Nonexistent** | No WHOIS or RDAP lookups in the active inference path. |
| **Headless JS Rendering** | Full DOM execution via browser | **Nonexistent** | Backend relies purely on static `requests.get()`. JS-generated credential forms are invisible to the parser. |
| **Scan History Persistence** | Telemetry logging & dashboard | **Partially Working** | Operates via in-memory list (max 200 records); data is lost on every backend restart. |
| **Security Operations Dashboard**| Filterable KPIs and history | **Implemented & Tested** | React dashboard renders statistics, charts, risk distribution, and historical cards cleanly. |

---

## 2. Automated Backend Test Suite Results

The automated Pytest suite located in `backend/tests/` was executed against the active Python 3.13.14 virtual environment.

### Test Execution Summary
- **Command:** `.\backend\venv\Scripts\python.exe -m pytest tests/`
- **Total Tests Collected:** 87 items
- **Total Passed:** 87 (100.0%)
- **Total Failed:** 0
- **Total Duration:** 120.19 seconds (2 minutes)
- **Warnings:** 3 (Starlette `httpx` deprecation warning, AnyIO Portal deprecation warning, and `urllib3` Unverified HTTPS warning for `example.com`).

### Breakdown by Test Module

| Test Module | Tests | Status | Scope / Coverage |
| :--- | :---: | :---: | :--- |
| `tests/test_api_enhanced.py` | 4 | **PASS** | `/api/analyze`, `/api/history`, `/api/stats`, `/api/history/clear` |
| `tests/test_api_predict.py` | 19 | **PASS** | `/health`, `/docs`, `/redoc`, payload validation, 422 errors, singleton reuse |
| `tests/test_build_training_dataset.py` | 4 | **PASS** | CSV feature alignment, missing values, column integrity |
| `tests/test_crawl_legitimate_deep_links.py` | 4 | **PASS** | Deep-crawling utilities and domain boundary limits |
| `tests/test_detection_engine.py` | 16 | **PASS** | End-to-end pipeline, SSRF filtering, HTML fallbacks, SPA bounding |
| `tests/test_fetch_html.py` | 6 | **PASS** | Byte capping (2 MB), timeouts, user-agent headers, SSL fallbacks |
| `tests/test_html_features.py` | 11 | **PASS** | Forms, password fields, iframe detection, external link ratio, meta refresh |
| `tests/test_stale_model_protection.py` | 3 | **PASS** | Model version metadata, SHA256 integrity, column mismatch rejection |
| `tests/test_train_baseline_models.py` | 4 | **PASS** | Baseline model fitting, StratifiedKFold cross-validation |
| `tests/test_tune_and_finalize_model.py` | 6 | **PASS** | GridSearchCV multi-metric tracking, scale_pos_weight calculation, joblib export |
| `tests/test_url_features.py` | 10 | **PASS** | Lengths, subdomains, IP hosts, `@` symbol, punycode, shorteners, delimiters |

---

## 3. Empirical Security Scenarios (Controlled Live Backend Evaluation)

Fifteen realistic scenarios were submitted directly to the running backend service at `http://127.0.0.1:8000/api/analyze` using a synthetic test harness ([test_audit_scenarios.py](file:///C:/Users/Udhaya/.gemini/antigravity-ide/brain/9a908033-1bdc-436b-9f7c-e0e33d8adb61/scratch/test_audit_scenarios.py)).

### Complete Results Matrix

| ID | Scenario Description | Input URL / Payload | HTTP | Time | Verdict | Score | Actual Behavior & Forensic Evidence |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **TC-01** | Known Legitimate URL | `https://www.google.com` (offline) | 200 | 25 ms | **Safe** | 20.0% | Clean domain, bounded to low risk. Indicators cite HTTPS and standard structure. |
| **TC-02** | Suspicious-Looking URL | `http://paypal-security-verification-portal.com/login/auth` | 200 | 17 ms | **Phishing** | 99.6% | Strong URL threat flags (HTTP + keywords + long domain). Triggered critical warning. |
| **TC-03** | Controlled Phishing Fixture | `http://secure-update-verify.top/login.php` + Credential Form | 200 | 19 ms | **Phishing** | 98.9% | Detected external form action to `malicious-collector.xyz`, password field, and `.top` TLD. |
| **TC-04a** | Raw Public IP Hostname | `http://198.51.100.25/login` | 200 | 17 ms | **Phishing** | 95.3% | `has_ip_address: true` + keyword triggered high-risk classification immediately. |
| **TC-04b** | SSRF Loopback Attack | `http://127.0.0.1:8000/docs` (fetch=True) | 200 | 16 ms | **Phishing** | 93.6% | SSRF Guard blocked HTTP fetch (`Direct loopback destination blocked`); URL evaluated as raw IP. |
| **TC-04c** | Cloud Metadata SSRF | `http://169.254.169.254/latest/meta-data/` | 200 | 16 ms | **Phishing** | 96.7% | SSRF Guard blocked IP fetch (`resolves to restricted internal IP 169.254.169.254`). |
| **TC-05** | Excessive Subdomains | `http://login.verify.account.update.security.bank.portal.com/auth` | 200 | 16 ms | **Phishing** | 98.8% | Correctly identified 6 subdomains and flagged deception indicators. |
| **TC-06** | Userinfo `@` Symbol | `http://legitimate-bank.com@attacker-controlled-server.com/signin` | 200 | 17 ms | **Phishing** | 99.6% | Detected destination obfuscation flag (`has_at_symbol: true`); classified as Critical. |
| **TC-07** | Percent Encoded Path | `https://example.com/%2e%2e/%2fadmin/login?next=...` | 200 | 18 ms | **Safe** | 20.0% | Encoded path recognized (`has_url_encoding: true`), but benign domain damped score to Safe. |
| **TC-08** | Double Slash Redirect | `http://trusted-site.com//evil.com/login` | 200 | 15 ms | **Phishing** | 94.0% | Flagged `has_double_slash_redirect: true` and non-HTTPS keyword threat. |
| **TC-09** | Unreachable Domain (Live) | `http://domain-does-not-exist-8472918374921.org/login` (fetch=True) | **TIMEOUT** | **10.0 s** | **FAILED** | — | **CRITICAL DEFECT:** Synchronous `socket.getaddrinfo()` stalled the backend, causing client HTTP timeout. |
| **TC-10** | Malformed Scheme | `javascript:alert(document.cookie)` | **TIMEOUT** | **10.0 s** | **FAILED** | — | **EVENT LOOP BLOCK:** Request was queued behind stalled TC-09 socket lookup, timing out before processing. |
| **TC-11** | Non-URL String | `this_is_definitely_not_a_valid_url` | 200 | 0.1 ms | **Error** | 0.0% | Handled safely after event loop cleared (`Invalid domain name or hostname`). |
| **TC-12** | High-Risk Known TLD | `http://billing-update-service.top/invoice` | 200 | 17 ms | **Phishing** | 98.8% | Compound threat (`.top` TLD + `billing`/`invoice` keywords) triggered Phishing verdict. |
| **TC-13** | Legitimate Deep Doc | `https://developer.mozilla.org/en-US/docs/Web/Security/.../TLS` | 200 | 17 ms | **Suspicious** | 47.4% | **FALSE POSITIVE:** Keyword "Security" in path triggered degraded medium risk on legitimate MDN doc! |
| **TC-14** | Suspicious Shortener | `http://bit.ly/login-verify-account` | 200 | 17 ms | **Phishing** | 97.1% | Correctly identified URL shortener slug concealing credential keywords. |
| **TC-15** | Client-Side SPA Shell | `https://modern-spa-app.com/dashboard` + React Root DOM | 200 | 20 ms | **Suspicious** | 48.0% | `is_likely_unrendered_spa_shell: true` correctly bounded ML prediction to 48%. |

---

## 4. Key Empirical Discoveries

### Discovery 1: Head-of-Line Event Loop Starvation (TC-09 & TC-10)
When TC-09 attempted to fetch an unreachable domain with `fetch_html: true`, Python's synchronous `socket.getaddrinfo()` call blocked inside the single-threaded asyncio event loop.
- Client timeout for TC-09 expired at 10,007 ms.
- Subsequent request TC-10 was blocked in the OS socket backlog and also timed out at 10,019 ms.
- Once the blocking DNS call timed out in Windows, the queue drained and TC-11 succeeded in 0.15 ms.
- **Security Impact:** An unauthenticated attacker sending 3 concurrent requests to dead hostnames can freeze the entire PhishGuard API service for all users.

### Discovery 2: False Positive on Legitimate Technical Content (TC-13)
When evaluating `https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS` without HTML:
- The keyword `Security` in the path triggered `has_suspicious_keywords: true`.
- Because HTML was not inspected, the model could not see MDN's 100+ legitimate internal navigation links.
- The system elevated the score to **47.4% ("Suspicious")** with the recommendation: *"EXERCISE CAUTION: Inspect the domain address bar carefully."*
- **Root Cause:** The model lacks a top-1M domain whitelist and relies on generic keyword substrings in paths.

---

## 5. Reproduction Instructions

To reproduce these exact results locally on Windows:

```powershell
# 1. Start the FastAPI backend
cd backend
.\venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2. In a second terminal, run the automated test suite
cd backend
.\venv\Scripts\python.exe -m pytest tests/ -v

# 3. Run the 15-scenario empirical test harness
.\backend\venv\Scripts\python.exe C:\Users\Udhaya\.gemini\antigravity-ide\brain\9a908033-1bdc-436b-9f7c-e0e33d8adb61\scratch\test_audit_scenarios.py
```

### Untested Areas & Justification
- **Live In-The-Wild Phishing Infrastructure:** Not tested to strictly honor rule #4 of the audit mandate (*"Do not launch destructive tests, exploit real websites, submit credentials, or perform unauthorized security testing"*). All phishing behaviors were evaluated using deterministic synthetic fixtures, offline datasets, and controlled unit mocks.
