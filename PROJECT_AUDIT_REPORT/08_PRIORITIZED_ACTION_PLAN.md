# PhishGuard AI — Prioritized Technical Action Plan

## 1. Action Plan Summary Matrix

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           PRIORITIZED ACTION ROADMAP                             │
├───────────────────┬──────────────────────────────────────────────────────────────┤
│ Tier 1: CRITICAL  │ Fix Event Loop Starvation DoS, Close SSRF Redirect Bypass,   │
│ (Security/Crash)  │ Restrict CORS & Protect Telemetry API.                      │
├───────────────────┼──────────────────────────────────────────────────────────────┤
│ Tier 2: HIGH      │ Active Extension Navigation Interception, Link Count ML      │
│ (Detection/Prev.) │ Feature Rebalancing, In-Browser DOM Inspection.              │
├───────────────────┼──────────────────────────────────────────────────────────────┤
│ Tier 3: MEDIUM    │ Public Suffix List (tldextract), Token URL Redaction,        │
│ (Robustness/Data) │ Top-1M Whitelist, SQLite History Persistence.                │
├───────────────────┼──────────────────────────────────────────────────────────────┤
│ Tier 4: OPTIONAL  │ Live WHOIS/Domain Age API, Brand Logo Perceptual Hashing,   │
│ (Enterprise Ready)│ Docker Compose Orchestration & Production NGINX Config.      │
└───────────────────┴──────────────────────────────────────────────────────────────┘
```

---

## 2. Tier 1: Critical Fixes (Immediate Remediation)

### Fix 1.1: Resolve Async Event Loop Starvation (CWE-400)
- **Target File:** `backend/app/api/routes/predict.py` & `backend/app/services/detection_engine.py`
- **Action:** Convert the blocking synchronous requests in `fetch_single_html` to asynchronous non-blocking calls or offload them to FastAPI's background threadpool.
- **Acceptance Criteria:**
  1. A request to an unresolvable hostname (`http://domain-does-not-exist.org`) must **never** block concurrent requests to `/health`, `/docs`, or other URLs.
  2. Submitting 10 concurrent requests to hanging addresses must not increase latency on concurrent `/api/analyze` requests for `https://google.com`.

### Fix 1.2: Close SSRF Redirect & DNS Rebinding Hole (CWE-918)
- **Target File:** `backend/app/services/detection_engine.py` (`fetch_single_html`)
- **Action:**
  1. Change `allow_redirects=True` to `allow_redirects=False`.
  2. Implement an explicit redirect handler loop (maximum 3 hops).
  3. Validate `is_safe_ssrf_destination` against the `Location` header host **before** each successive HTTP GET.
- **Acceptance Criteria:**
  1. An HTTP 302 redirect from a benign public host to `http://169.254.169.254/` or `http://127.0.0.1:8000/` must be intercepted and immediately rejected with `SSRF Guard: Restricted redirect destination`.

### Fix 1.3: Eliminate Wildcard CORS & Secure Telemetry Endpoints (CWE-942)
- **Target File:** `backend/app/main.py` & `backend/app/api/routes/predict.py`
- **Action:**
  1. Replace `allow_origins=["*"]` with an explicit whitelist: `["http://localhost:5173", "http://127.0.0.1:5173"]`.
  2. Protect `/api/history` and `/api/history/clear` so that arbitrary web pages opened in browser tabs cannot harvest scan records.
- **Acceptance Criteria:**
  1. Cross-origin JavaScript requests from external origins (e.g., `http://evil.com`) to `http://127.0.0.1:8000/api/history` must be rejected by CORS preflight (`403 Forbidden` / No `Access-Control-Allow-Origin`).

---

## 3. Tier 2: High-Priority Improvements (Core Detection & Prevention)

### Fix 2.1: Implement Active Browser Navigation Interception
- **Target Files:** `extension/manifest.json`, `extension/background/service-worker.js`, `extension/warning/warning.js`
- **Action:**
  1. Request `webNavigation` and `declarativeNetRequest` permissions in `manifest.json`.
  2. In `service-worker.js`, register `chrome.webNavigation.onBeforeNavigate`.
  3. Check the target URL against a local cache or fast backend check before navigation completes.
  4. If verdict is `phishing`, redirect the tab immediately to `warning/warning.html?url=...` **before** the malicious page loads or executes JavaScript.
- **Acceptance Criteria:**
  1. When a user enters a known high-risk phishing URL into the browser omnibox, the browser renders the warning interstitial page without ever executing scripts on the target domain.

### Fix 2.2: Rebalance Machine Learning Features to Eliminate Link-Count Bias
- **Target Files:** `backend/ml/feature_extraction/html_features.py`, `backend/ml/training/tune_and_finalize_model.py`
- **Action:**
  1. Replace raw `num_links` and `num_internal_links` with normalized features:
     - `link_density_ratio = num_links / max(1, visible_text_length)`
     - `internal_to_external_link_ratio = num_internal_links / max(1, num_external_links)`
  2. Retrain XGBoost with tighter column subsampling (`colsample_bytree <= 0.6`).
- **Acceptance Criteria:**
  1. Top-2 feature importance concentration must drop from 43.1% to below 25%.
  2. Legitimate Single Page Applications with `< 10` links must no longer be automatically classified as phishing.

### Fix 2.3: In-Browser Live DOM Extraction via Content Scripts
- **Target Files:** `extension/manifest.json`, `extension/content/scanner-content.js`
- **Action:**
  1. Extract DOM features (forms, inputs, password fields, script count) directly from the running browser tab DOM via an injected content script rather than re-fetching static HTML on the backend.
  2. Send the extracted DOM vector alongside the URL to `/api/analyze`.
- **Acceptance Criteria:**
  1. Phishing pages dynamically rendered by client-side JavaScript are inspected with 100% feature visibility, resolving the static HTML visibility gap.

---

## 4. Tier 3: Medium-Priority Improvements (Robustness & Maintainability)

### Fix 3.1: Integrate Public Suffix List via `tldextract`
- **Target File:** `backend/ml/feature_extraction/url_features.py`
- **Action:** Replace manual `len(hostname.split(".")) - 2` with `tldextract.extract(url)`.
- **Acceptance Criteria:**
  1. `example.co.uk` and `university.ac.in` must evaluate to `num_subdomains = 0`.
  2. `login.example.co.uk` must evaluate to `num_subdomains = 1`.

### Fix 3.2: Redact Sensitive Query Parameters in Logging and History
- **Target Files:** `backend/app/api/routes/predict.py`, `backend/app/services/history_service.py`
- **Action:** Strip or mask query string values for sensitive parameter keys (`token`, `password`, `code`, `auth`, `key`, `session`) before logging or adding to history.
- **Acceptance Criteria:**
  1. A scanned URL `https://bank.com/reset?token=secret123` must appear as `https://bank.com/reset?token=[REDACTED]` in application logs and `/api/history`.

### Fix 3.3: Clean Up Dead Code and Orphaned Components
- **Action:** Delete orphaned `frontend/src/pages/About.jsx` and archive obsolete experimental sweeps in `scratch/`.
- **Acceptance Criteria:**
  1. `frontend/src/pages/AboutPage.jsx` remains active; build succeeds cleanly with no missing imports.

---

## 5. Tier 4: Optional Enhancements (Enterprise Maturation)

1. **Domain Registration Age Query (RDAP / WHOIS):**  
   Add a fast, cached RDAP client to flag domains registered `< 14 days ago`.
2. **Brand Impersonation & Visual Perceptual Hashing:**  
   Compare webpage favicons, page titles, and rendered logos against targeted high-value financial and tech brands.
3. **Database Persistence:**  
   Replace the in-memory Python list in `HistoryService` with SQLite (via SQLModel or SQLAlchemy) for persistent telemetry across server restarts.
4. **Containerization & Deployment Configuration:**  
   Create a multi-stage `Dockerfile` and `docker-compose.yml` for unified deployment of the FastAPI backend and NGINX-served frontend.
