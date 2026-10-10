# PhishGuard AI — High-Risk Warning Flow & Interception Verification Report

**Report Classification:** Security Engineering Investigation & Real Chromium Interception Verification  
**Component:** Extension Background Service Worker (`service-worker.js`), Warning Interstitial (`warning.html` / `warning.js`), Backend Risk Evaluation (`risk_scoring.py`, `detection_engine.py`)  
**Date:** October 2026  
**Auditor / Engineer:** Senior Cybersecurity, Browser Extension Security & ML Application Engineer  
**Status:** **INVESTIGATED, EXECUTED & VERIFIED IN REAL CHROMIUM**  
**Preceding Deliverables:**
- [GOOGLE_RISK_SCORE_MISMATCH_INVESTIGATION.md](file:///c:/Users/Udhaya/S5_Phishing_Detector/PROJECT_AUDIT_REPORT/PHASE_2_EXTENSION_BLOCKING/GOOGLE_RISK_SCORE_MISMATCH_INVESTIGATION.md)
- [GOOGLE_RISK_SCORE_MISMATCH_FIX_REPORT.md](file:///c:/Users/Udhaya/S5_Phishing_Detector/PROJECT_AUDIT_REPORT/PHASE_2_EXTENSION_BLOCKING/GOOGLE_RISK_SCORE_MISMATCH_FIX_REPORT.md)

---

## 1. Investigation of `http://example.com/login` (87.7% Risk Score)

### Observed Backend Output
A backend request for `http://example.com/login` with `fetch_html: false` (degraded mode) returned:
- **Status:** `phishing`
- **Risk Score:** `87.7%`
- **Risk Level:** `high`
- **Model Confidence:** `0.8772`
- **Detected Indicators:**
  1. *URL contains sensitive or authentication-related keywords (e.g., login, verify, account, secure).*
  2. *Connection does not use secure HTTPS encryption.*
  3. *Live HTML content could not be inspected (site unreachable); high-risk verdict is driven by strong URL-level threat signals.*

### Root Cause Analysis: Is `http://example.com/login` a False Positive?
**Yes, technically it is a false positive**, but it is an understandable, deterministic consequence of the current heuristic and ML pipeline:

1. **RFC 2606 Special-Use Domain**:
   - `example.com`, `example.net`, `example.org`, and `.example` are reserved by the IETF / IANA under RFC 2606 specifically for documentation, examples, and testing. There is no legitimate credential-harvesting or banking infrastructure hosted on `example.com`.
2. **Lexical ML Model Features**:
   - The trained XGBoost model evaluates lexical URL features:
     - `uses_https = False` (0)
     - `has_suspicious_keywords = True` (1, due to `/login`)
     - `path_length = 6`
     - `num_slashes = 3`
     - `path_depth = 1`
   - In the training corpus, unencrypted HTTP URLs containing `/login` overwhelmingly represent credential-harvesting phishing kits. The model outputs a raw probability of `0.8772` (87.72%).
3. **Phase 1 Degraded-Mode Policy Interaction**:
   - In `backend/app/services/risk_scoring.py`:
     ```python
     def has_strong_url_threat_signals(url_features: Dict[str, Any]) -> bool:
         ...
         if not uses_https and (has_kw or has_tld or subdomains >= 3 or is_shortened):
             return True
     ```
   - Because `uses_https` is `False` and `has_suspicious_keywords` is `True`, `has_strong_url_threat_signals()` evaluates to `True`.
   - In `map_status_and_risk()`, URLs with active threat signals **bypass degraded-mode confidence dampening** (`adjusted_prob = round(phishing_probability, 4)`).
   - Consequently, the model's unconstrained 87.7% probability is assigned, elevating the verdict to `phishing` / `high`.
4. **Distinction Between True Attack vs. Insecure Pattern**:
   - From a generic network security standpoint, transmitting credentials over unencrypted HTTP (`http://.../login`) is inherently insecure.
   - However, since `example.com` cannot host malicious infrastructure, treating it as an active phishing attack site represents a benign false positive caused by the absence of an RFC 2606 reserved domain exemption.

---

## 2. Audit of Existing Extension Interception & Warning Tests

Existing Phase 2 tests were examined to determine whether they exercised the real browser extension service worker in Chromium or relied on mocks:

### A. `extension/tests/test_extension_blocking.mjs`
- **Execution Environment:** Node.js standalone runtime (`node extension/tests/test_extension_blocking.mjs`).
- **Mechanism:** Imports `service-worker.js` as a CommonJS module using `createRequire`.
- **Mocking Extent:**
  - `globalThis.chrome` is entirely mocked (in-memory arrays capture `tabs.update` and `action.setBadgeText` calls).
  - `globalThis.fetch` is mocked to return hardcoded JSON objects.
  - Test functions invoke `handleBeforeNavigate({ tabId: 101, url: '...', frameId: 0 })` directly via JavaScript function calls.
- **Finding:** **Does NOT execute in Chromium.** It validates JavaScript branching logic in isolation, but does not test real browser extension APIs, browser lifecycle, or actual Chromium navigation events.

### B. `extension/tests/test_browser_extension_e2e.mjs`
- **Execution Environment:** Real Chromium browser launched via Puppeteer with `--load-extension`.
- **Mechanism:**
  - Verified that the extension manifest loaded into Chromium without errors.
  - Inspected `browser.targets()` to check that the background service worker target initialized.
  - Tested the warning page by directly navigating to `file:///.../warning/warning.html?url=...&risk=94.5...`.
- **Finding:** **Did NOT exercise navigation interception.** While it proved that `warning.html` renders correctly when opened directly, it bypassed the background service worker entirely. No browser navigation event was dispatched, and `chrome.webNavigation.onBeforeNavigate` was never triggered inside Chromium.

---

## 3. Controlled High-Risk Navigation Interception Test

To close this verification gap safely and without external network communication, a controlled test was designed, implemented, and executed:
**Test File:** `extension/tests/test_controlled_high_risk_interception.mjs`.

### Test Architecture & Constraints
1. **Zero External Traffic**:
   - Spins up a local loopback HTTP server (`http://127.0.0.1:<ephemeral-port>/login`) using Node.js `http.createServer`.
   - No external domains or remote network interfaces are contacted.
2. **Real Chromium Runtime**:
   - Launches headless Chromium with the unpacked PhishGuard AI extension loaded.
3. **Real Background Service Worker Hook**:
   - Locates the active `service_worker` target in Chromium: `chrome-extension://<id>/background/service-worker.js`.
   - Obtains the WebWorker handle (`await swTarget.worker()`).
4. **Synthetic High-Risk API Injection**:
   - Injects a synthetic high-risk API response into the service worker's `fetch` handler modeling the exact output of `http://example.com/login`:
     ```json
     {
       "status": "phishing",
       "risk_level": "high",
       "risk_score": 87.7,
       "confidence": 0.8772,
       "is_phishing": true,
       "detected_indicators": [
         "URL contains sensitive or authentication-related keywords (e.g., login, verify, account, secure).",
         "Connection does not use secure HTTPS encryption.",
         "Live HTML content could not be inspected (site unreachable); high-risk verdict is driven by strong URL-level threat signals."
       ]
     }
     ```
5. **Real Navigation Trigger**:
   - A Chromium tab navigates to the controlled local URL (`http://127.0.0.1:<port>/login`).
   - Chromium fires the real `chrome.webNavigation.onBeforeNavigate` event to the background service worker.
   - The service worker evaluates the URL, detects `risk_score: 87.7 >= 70`, and invokes `chrome.tabs.update()` to redirect the tab.
   - Chromium aborts the in-flight destination request (`net::ERR_ABORTED`) and loads the extension warning page.

---

## 4. Empirical Test Execution & Results

### Command Executed
```powershell
node extension/tests/test_controlled_high_risk_interception.mjs
```

### Exact Execution Output
```
===============================================================
 PhishGuard AI — Controlled High-Risk Navigation Interception
===============================================================
✓ Local test server bound to loopback: http://127.0.0.1:58448/login (ZERO external traffic)
Launching real Chromium with unpacked extension: C:\Users\Udhaya\S5_Phishing_Detector\extension...
✓ Real Chromium launched successfully.
✓ Active Background Service Worker detected: chrome-extension://gddfamcpmommlenakeomgaelblbkdnnb/background/service-worker.js
✓ Synthetic high-risk API response injected into Service Worker fetch handler.
Navigating tab to target URL: http://127.0.0.1:58448/login...
ℹ Initial navigation intercepted by extension (net::ERR_ABORTED at http://127.0.0.1:58448/login)
✓ Tab successfully intercepted & redirected to warning page:
  chrome-extension://gddfamcpmommlenakeomgaelblbkdnnb/warning/warning.html?url=http%3A%2F%2F127.0.0.1%...

--- Forensic Verification in Real Chromium DOM ---
  - Target URL displayed: "http://127.0.0.1:58448/login"
  - Risk Score displayed: "87.7%"
  - Risk Badge displayed: "CRITICAL PHISHING THREAT"
  - Threat items count:   3
      [1] URL contains sensitive or authentication-related keywords (e.g., login, verify, account, secure).
      [2] Connection does not use secure HTTPS encryption.
      [3] Live HTML content could not be inspected (site unreachable); high-risk verdict is driven by strong URL-level threat signals.
✓ Override panel expands correctly in warning interstitial.
===============================================================
 CONTROLLED TEST RESULT: ALL ASSERTIONS PASSED (100% SUCCESS)
===============================================================
```

---

## 5. Summary Matrix: Executed vs. Mocked vs. Unverified

| Component / Layer | What Was Actually Executed | What Was Mocked / Simulated | Status & Verification Boundary |
| :--- | :--- | :--- | :--- |
| **Browser Runtime** | Real Chromium browser launched via Puppeteer with unpacked extension loaded. | None. | **VERIFIED** in real Chromium process. |
| **Service Worker** | Actual Manifest V3 background service worker initialized and running in browser. | None. | **VERIFIED** in Chromium service worker target. |
| **Navigation Event** | Real `chrome.webNavigation.onBeforeNavigate` event fired by browser tab navigation. | Destination was local loopback (`127.0.0.1:<port>`) to avoid external traffic. | **VERIFIED** via real browser event dispatch. |
| **Backend API Evaluation** | Real worker function `evaluateUrlWithBackend()` and cache lookups executed. | Worker's `fetch()` call intercepted to return synthetic 87.7% high-risk response. | **CONTROLLED**: Prevents external API dependence and guarantees determinism. |
| **Tab Interception** | Real `chrome.tabs.update()` call issued by worker; Chromium aborted original page request. | None. Chromium natively reported `net::ERR_ABORTED`. | **VERIFIED**: Proven active redirection in browser. |
| **Warning Interstitial DOM** | Real `warning.html` loaded in tab; parsed query parameters; rendered DOM elements. | None. Rendered directly in Chromium tab DOM. | **VERIFIED**: 87.7%, target URL, badge, and 3 threats validated via `$eval`. |
| **User Override Panel** | Real click on `#toggle-override-btn`; verified `#override-panel` CSS visibility toggle. | None. | **VERIFIED** in real Chromium DOM. |
| **Manifest V3 Async Race** | Browser dispatches initial navigation concurrently with async risk check. | N/A (tested on fast local loopback). | **KNOWN LIMITATION**: Manifest V3 does not guarantee pre-request synchronous blocking. |
| **ML Model on `example.com`** | Python analysis confirmed 87.7% raw score from `phishing_model.joblib`. | Model was not retrained or modified (per task restrictions). | **IDENTIFIED LIMITATION**: Benign false positive on reserved RFC 2606 domain. |

---

## 6. Complete Extension Test Suite Status

All three extension test suites were executed sequentially and are fully passing:

```powershell
node extension/tests/test_extension_blocking.mjs
node extension/tests/test_browser_extension_e2e.mjs
node extension/tests/test_controlled_high_risk_interception.mjs
```

- **`test_extension_blocking.mjs`:** 11 / 11 unit tests passed (100%).
- **`test_browser_extension_e2e.mjs`:** Static Chromium DOM & popup checks passed (100%).
- **`test_controlled_high_risk_interception.mjs`:** Real Chromium end-to-end interception passed (100%).
- **Backend Tests:** 124 / 124 backend Pytest tests passed.
- **Failures / Errors:** **0 failed, 0 errors.**
