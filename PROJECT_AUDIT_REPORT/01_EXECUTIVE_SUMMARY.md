# PhishGuard AI — Complete Cybersecurity Project Audit & Technical Assessment

## Executive Summary & System Overview

**Project Title:** Real-Time AI/ML-Based Phishing Detection and Prevention System  
**System Name:** PhishGuard AI  
**Audit Classification:** Independent Defensive Security & Architecture Assessment  
**Audit Date:** October 2026  
**Auditor:** Senior Cybersecurity Engineer, Application Security Auditor & ML Engineer  
**Workspace Root:** `c:\Users\Udhaya\S5_Phishing_Detector`  

---

### 1. Plain-English Summary

**PhishGuard AI** is an academic cybersecurity demonstration platform designed to evaluate web addresses for phishing characteristics. It pairs a **Python FastAPI backend** hosting an **XGBoost 2.1.0 machine learning classifier** with a **React 18 + Vite frontend web dashboard** and a **Manifest V3 Chromium browser extension**.

The platform extracts a total of **43 numerical and boolean features** (22 lexical/structural URL features and 21 HTML features) from a target website, executes model inference, bounds the resulting risk score under degraded conditions (e.g., when the website cannot be fetched or is a JavaScript Single Page Application), and displays a risk percentage (0–100%), classification badge (Safe, Suspicious, Phishing), and actionable security recommendations.

---

### 2. What the System Genuinely Does Today

1. **Extracts 22 Lexical URL Features Offline:**  
   Parses target URLs using Python standard library `urllib.parse` and regexes to extract structural metrics (lengths, character counts, subdomains, path depth, hex/percent encodings) and binary heuristic flags (`has_ip_address`, `has_at_symbol`, `has_double_slash_redirect`, `has_suspicious_tld`, `has_suspicious_keywords`, `is_shortened_url`). This process executes in under 1 millisecond and never raises exceptions.

2. **Performs Server-Side Static HTML Inspection:**  
   If permitted, the backend issues an HTTP GET request to the target website using `requests.get()`, downloads the static response (capped at 2 MB), and parses the DOM with `BeautifulSoup` (`lxml` / `html.parser`). It extracts 21 features covering form inputs, password fields, external form action targets, link ratios, mismatched anchor text, hidden iframes, meta-refresh redirects, and suspicious script strings.

3. **Executes XGBoost Inference (Candidate A4 Champion):**  
   Runs an ensemble gradient boosted decision tree model (`phishing_model.joblib`, 43 features, `max_depth=4`, `colsample_bytree=0.7`, `scale_pos_weight=5.0`, `n_estimators=200`) trained on 7,111 samples and evaluated on 1,799 samples with 0.00% domain leakage.

4. **Applies Risk Calibration & Degraded-Mode Heuristic Bounding:**  
   When the target site is unreachable or detected as a client-side Single Page Application (SPA) shell, the backend dampens the ML probability (capping it at `<= 0.48` / "Suspicious") unless independent strong URL threat signals (raw IP, `@` symbol, double slash redirect, or suspicious TLD + keywords) are present.

5. **Provides a Modern Web Operations Center & Extension Simulator:**  
   A React 18 single-page application displays an interactive cyber workbench, radar visualizer, circular risk gauge, tabbed signals breakdown, recent scan history, and extension simulator.

6. **Provides a Chromium MV3 Advisory Extension:**  
   A browser extension popup queries the backend `/api/analyze` endpoint for the active tab's URL and renders a circular SVG gauge, verdict badge, indicator lists, and an optional button to open a safe warning interstitial (`warning.html`).

---

### 3. What the System DOES NOT Do (Critical Distinctions)

- ❌ **Does NOT Actively Block Browser Navigation:**  
  The extension contains **zero** active interception mechanisms (`chrome.webNavigation.onBeforeNavigate`, `chrome.declarativeNetRequest`, or content script redirection). Malicious websites continue loading and running JavaScript unimpeded. The user must manually click the extension icon to view the risk score.
- ❌ **Does NOT Render Dynamic JavaScript in the Backend:**  
  The backend inspects static HTTP responses using `requests.get()`. It does not run a headless browser (Puppeteer, Playwright, or Selenium) during live analysis. Phishing pages generated dynamically via JavaScript appear blank or trigger degraded SPA mode.
- ❌ **Does NOT Inspect TLS/SSL Certificates:**  
  The backend fetches HTML with `verify=False` (ignoring certificate validity, issuer, age, revocation, and SANs).
- ❌ **Does NOT Query WHOIS, RDAP, or External Threat Feeds:**  
  Domain age, registrar, registration date, Google Safe Browsing, and VirusTotal are **not** checked during inference.
- ❌ **Does NOT Perform Visual or Brand Logo Matching:**  
  There is no computer vision, screenshot comparison, or perceptual hashing for brand impersonation.
- ❌ **Does NOT Enforce Backend Authentication or Multi-Tenant Isolation:**  
  All REST endpoints (`/api/analyze`, `/api/history`, `/api/history/clear`, `/api/stats`) are unauthenticated with wildcard CORS (`allow_origins=["*"]`).

---

### 4. Strongest Features

1. **Strict Zero-Leakage Dataset Evaluation:**  
   The active production model (Candidate A4) was partitioned using `GroupShuffleSplit` on registered domains, guaranteeing 0.00% train/test domain overlap and preventing artificial accuracy inflation.
2. **Defensive Lexical Feature Architecture:**  
   The URL feature extractor is pure, resilient, offline, and handles malformed strings without unhandled exceptions.
3. **Transparent Degraded-Mode Reasoning:**  
   Instead of outputting false high-confidence predictions when a site is unreachable or an empty SPA shell, the system explicitly documents its visibility limits in human-readable indicators and dampens ungrounded scores.
4. **Comprehensive Automated Test Suite:**  
   The backend includes 87 automated unit and integration tests across API routes, SSRF protections, feature extraction, and ML pipelines, all passing with zero test failures.
5. **Polished Frontend User Experience:**  
   The web dashboard provides clear security communication, tabbed telemetry, and an intuitive cyber aesthetic.

---

### 5. Biggest Cybersecurity Weaknesses

1. **Event Loop Starvation / Denial of Service via Synchronous Network Calls:**  
   FastAPI `async def predict_url` calls synchronous blocking functions (`requests.get()` and `socket.getaddrinfo()`). When a target host is unreachable, the entire Python asyncio event loop freezes for up to 8–10 seconds, stalling all concurrent API requests across the system.
2. **Advisory-Only Extension Architecture (Zero Prevention Guarantee):**  
   The extension cannot prevent a user from submitting credentials to a phishing site because it never halts or intercepts initial navigation. The warning page is only opened in a separate tab if the user manually clicks a button inside the popup.
3. **Severe ML Feature Dominance on Link Counts (43.1% Split Weight):**  
   `num_links` (26.5%) and `num_internal_links` (16.6%) dominate model decisions. Legitimate websites with few links (single-page sites, documentation portals, portfolio landing pages) are heavily biased toward phishing classifications.
4. **CORS Wildcard & Unauthenticated Local History Exfiltration:**  
   Any website visited by the user in any browser tab can execute a JavaScript `fetch('http://127.0.0.1:8000/api/history')` to exfiltrate the user's complete history of scanned URLs and security telemetry without authentication.
5. **SSRF Redirect & DNS Rebinding Bypass (`allow_redirects=True`):**  
   The SSRF guard only inspects the initial hostname before calling `requests.get(..., allow_redirects=True)`. An external server returning an HTTP 302 redirect to `http://169.254.169.254/` or `http://127.0.0.1:8000/` completely bypasses the pre-request IP filter.

---

### 6. Five Most Important Recommendations

| Priority | Area | Required Action |
| :---: | :--- | :--- |
| **P1** | **Backend Reliability** | Migrate `fetch_single_html` to `httpx.AsyncClient` or run synchronous calls in a background threadpool (`run_in_threadpool`) to stop event loop freezing. |
| **P2** | **Extension Prevention** | Implement `chrome.declarativeNetRequest` or `chrome.webNavigation.onBeforeNavigate` with an asynchronous cache lookup to intercept high-risk loads before page execution. |
| **P3** | **API Security & Privacy** | Lock down CORS to explicit dashboard origins, remove full URLs from unauthenticated telemetry endpoints, and sanitize query parameter tokens before logging. |
| **P4** | **SSRF Hardening** | Disable automated redirects (`allow_redirects=False`), re-verify IP addresses on each redirect hop, and bind requests directly to resolved IP sockets. |
| **P5** | **ML Feature Rebalancing** | Retrain the model with link-density ratios rather than raw counts, or enforce feature sub-sampling to eliminate the 43% link-count bias that penalizes legitimate low-link websites. |

---

### 7. Overall Readiness & Maturity Assessment

```
[ Concept ] -> [ Academic Prototype ] -> [ Tested Research Prototype ] -> [ Pilot Candidate ] -> [ Production ]
                                 ▲
                          CURRENT LEVEL
                  (Tested Research Prototype)
```

**Classification:** **Tested Research Prototype**  
PhishGuard AI is an impressive, well-documented, and thoughtfully evaluated academic capstone and research demonstrator. Its zero-leakage evaluation, extensive test suite, and clear separation of signal groups demonstrate strong software engineering fundamentals. However, due to its advisory-only browser extension design, event loop blocking vulnerability, SSRF redirect bypass, and lack of authentication, it is **not suitable for production deployment** without architectural remediation.

---

### 8. Category Scorecard (0 to 5)

| Category | Score | Justification & Evidence Reference |
| :--- | :---: | :--- |
| **Detection Quality** | **3.0 / 5** | Strong lexical URL heuristics and fast inference; hindered by static HTML limitations and lack of headless JS rendering. |
| **Prevention Effectiveness** | **1.0 / 5** | Detection only. No automatic navigation blocking, no webNavigation intercept, warning opens in new tab only upon manual button press. |
| **ML Evaluation Quality** | **4.0 / 5** | Domain-grouped split with 0.00% leakage, comprehensive candidate comparisons; docked for heavy 43% feature dominance on link counts. |
| **False-Positive Handling** | **3.0 / 5** | Thoughtful SPA and degraded mode bounding logic; however, legitimate documentation and low-link pages still trigger false "Suspicious" verdicts. |
| **False-Negative Handling** | **2.5 / 5** | High recall on conventional phishing kits; vulnerable to modern PaaS-hosted phishing, JS obfuscation, and zero-day clean URLs. |
| **Extension Reliability** | **2.0 / 5** | Clean UI and gauge display; relies entirely on manual popup opening, background service worker does not monitor navigations. |
| **Backend Security** | **2.0 / 5** | Event loop starvation DoS on slow hosts, SSRF redirect bypass, unauthenticated API history, and disabled SSL verification. |
| **Privacy & Data Ethics** | **2.5 / 5** | Zero external tracking, but full URLs with authentication tokens/query params are retained in memory and exposed over open CORS. |
| **Testing & Reproducibility**| **4.5 / 5** | 87 passing automated tests, clear seed reproducibility, clean dataset manifests, and comprehensive evaluation scripts. |
| **Maintainability** | **3.5 / 5** | Clean modular structure in backend and frontend; minor dead code in frontend (`About.jsx`) and extensive experimental artifacts in `scratch/`. |
| **Documentation** | **4.5 / 5** | Outstanding documentation suite in `docs/` detailing baseline comparisons, ablation studies, and architectural decisions. |
| **Deployment Readiness** | **1.5 / 5** | Lacks authentication, container orchestration, rate limiting, production CORS hardening, and persistent database storage. |
