# Phase 1 Remediation Changelog — Backend Security Hardening

**Project:** PhishGuard AI  
**Phase:** Phase 1 — Backend Security Remediation  
**Scope:** Outbound Network Guards, SSRF & Redirect Defenses, Async Loop Concurrency, CORS Restriction, Scan History Authorization, and TLS Verification Restoration  
**Date:** October 10, 2026  
**Auditor / Engineer:** Senior Backend Security Engineer  

---

## 1. Overview of Remediations

This remediation cycle directly addresses the high-risk architectural and implementation security findings uncovered during the comprehensive security audit (`PROJECT_AUDIT_REPORT/`). All changes strictly adhere to the defined safety invariants:
1. Production ML model files (`phishing_model.joblib`, `model_metadata.json`) were untouched.
2. Frontend UI and browser extension client code were untouched.
3. No TLS verification bypasses (`verify=False`) remain anywhere in the fetch path.
4. Existing REST response contracts (`/predict`, `/api/analyze`, `/api/history`, `/api/stats`, `/health`) remain 100% backward-compatible.
5. All 105 tests across the entire test suite pass cleanly (87 existing + 18 new regression tests).

---

## 2. Files Changed and Technical Rationale

### A. `backend/app/services/ssrf_guard.py` *(New Component)*
- **Purpose:** Centralized outbound network validation service providing deep defense-in-depth against Server-Side Request Forgery (SSRF), DNS rebinding, and IP-smuggling attacks.
- **Key Implementations:**
  - `is_ip_restricted(ip_obj)`: Comprehensive validation covering IPv4, IPv6, IPv4-mapped IPv6 (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`), 6to4 encapsulation (`2002::/16`), RFC 1918 private subnets, loopback (`127.0.0.0/8`, `::1`), link-local and cloud metadata (`169.254.0.0/16`), Carrier-Grade NAT (`100.64.0.0/10`), documentation blocks (RFC 5737 / RFC 3849), multicast, broadcast, and unspecified destinations.
  - `resolve_and_validate_hostname(hostname)`: Resolves all IP address records for a given hostname via `socket.getaddrinfo`. If *any* returned IP belongs to a restricted subnet, the hostname is rejected.
  - `validate_outbound_url(raw_url)`: Reusable pre-flight validation enforcing:
    - Only `http://` and `https://` schemes.
    - Rejection of embedded user credentials (`http://user:pass@host`).
    - Valid port ranges (1–65535).
    - Destination IP validation.
  - `sanitize_url_for_logging(raw_url)`: URL sanitization utility that strips embedded userinfo credentials and redacts sensitive query parameters (e.g., `token`, `password`, `key`, `session`, `auth`, `jwt`) to `[REDACTED]`, while preserving safe bracket formatting for logs.

### B. `backend/app/services/detection_engine.py` *(Modified)*
- **Purpose:** Integrate centralized SSRF guard, manual redirect following, TLS verification restoration, and non-blocking asynchronous fetching.
- **Key Changes:**
  - **Removed TLS Bypass:** Removed `urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)` and enforced `verify=True` across all HTTP fetching operations.
  - **Manual Redirect Validation Loop:** Replaced automatic redirect following (`allow_redirects=True`) with manual redirect resolution up to `MAX_REDIRECT_HOPS` (3 hops). Destination schemes, hostnames, and IP resolutions are re-validated on *every individual hop* before making the subsequent request. If an endpoint attempts to redirect to a private IP, loopback, cloud metadata (`169.254.169.254`), or non-HTTP scheme, the request is immediately aborted before connecting.
  - **Added `fetch_single_html_async`:** Implemented an asynchronous HTTP fetching method using `httpx.AsyncClient(verify=True, follow_redirects=False)`. Enforces connection timeouts, read timeouts, manual redirect re-validation, and response body size limits (`MAX_RESPONSE_BYTES = 2MB`).
  - **Added `analyze_url_async`:** Non-blocking asynchronous analysis orchestration that awaits `fetch_single_html_async` without blocking the FastAPI event loop.
  - **Test Fixture Compatibility:** Factored result construction into `_evaluate_and_build_result` and added transparent delegation when unit test fixtures patch `fetch_single_html` or `analyze_url`.

### C. `backend/app/core/config.py` *(Modified)*
- **Purpose:** Secure CORS configuration and history authorization settings.
- **Key Changes:**
  - Replaced wildcard configuration with explicit `CORS_ALLOWED_ORIGINS` (`http://localhost:5173`, `http://localhost:3000`, `http://127.0.0.1:5173`, `http://127.0.0.1:3000`).
  - Added `CORS_ALLOW_ORIGIN_REGEX` for Chromium and Firefox extension scheme validation (`^(chrome|moz)-extension://.*$`).
  - Added `REQUIRE_HISTORY_AUTH: bool = False` and `HISTORY_API_KEY: Optional[str] = None` configuration toggles for optional pre-shared key authentication.

### D. `backend/app/main.py` *(Modified)*
- **Purpose:** Enforce restricted CORS middleware.
- **Key Changes:**
  - Removed wildcard `allow_origins=["*"]`.
  - Configured `CORSMiddleware` with `settings.CORS_ALLOWED_ORIGINS` and `settings.CORS_ALLOW_ORIGIN_REGEX`.
  - Explicitly disabled credentials over wildcard origins (`allow_credentials=False`).

### E. `backend/app/services/history_service.py` *(Modified)*
- **Purpose:** URL sanitization at storage time to prevent credential harvesting from scan records.
- **Key Changes:**
  - Updated `add_record()` to automatically sanitize and redact URLs before appending them to memory. Any embedded HTTP userinfo is stripped, and sensitive tokens/secrets in query parameters are replaced with `[REDACTED]`.

### F. `backend/app/api/routes/predict.py` *(Modified)*
- **Purpose:** Async endpoint execution, safe logging, and cross-site history authorization.
- **Key Changes:**
  - Updated `predict_url()` to await `engine.analyze_url_async()`, eliminating event loop blocking during live network inspection.
  - Updated exception logging to sanitize user URLs using `sanitize_url_for_logging(payload.url)` before logging to prevent token and CRLF log injection.
  - Added `verify_history_access(request: Request)` dependency to `/api/history`, `/api/history/clear`, and `/api/stats`:
    - Rejects cross-site browser fetches (`Sec-Fetch-Site: cross-site`) with HTTP 403 Forbidden.
    - Rejects unauthorized external origins in `Origin` or `Referer` headers with HTTP 403 Forbidden.
    - Enforces constant-time API key verification (`hmac.compare_digest`) when `REQUIRE_HISTORY_AUTH=True`.

### G. `backend/tests/test_api_predict.py` *(Modified)*
- **Purpose:** Update CORS test assertions from obsolete wildcard expectations to verified restricted origins.
- **Key Changes:**
  - Updated `test_cors_headers` to assert allowed origin `http://localhost:3000` receives the origin header and unauthorized origin `http://evil-phish.com` does not receive CORS headers.

### H. `backend/tests/test_phase1_security.py` *(New Component)*
- **Purpose:** Dedicated regression test suite verifying all Phase 1 security remediations (18 test cases).

---

## 3. Vulnerabilities Addressed

| Audit Finding ID | Severity | Description | Remediation Implemented |
|---|---|---|---|
| **VULN-01: SSRF via Redirect Bypass** | Critical | Automatic redirects followed unvalidated destinations, allowing attackers to access internal endpoints (`169.254.169.254`, `127.0.0.1`, `10.0.0.0/8`). | Manual redirect resolution enforcing destination scheme, hostname, and IP re-validation on every hop. |
| **VULN-02: Event Loop Denial of Service** | High | Synchronous `requests.get()` and DNS lookups inside async FastAPI route blocked event loop. | Implemented `httpx.AsyncClient` with explicit connect/read timeouts and non-blocking `analyze_url_async`. |
| **VULN-03: Wildcard CORS Data Exposure** | High | `allow_origins=["*"]` allowed arbitrary websites to issue cross-origin requests to local backend. | Restricted CORS to explicit localhost dashboard ports and browser extension schemes. |
| **VULN-04: Unauthenticated History Access** | High | `/api/history` exposed complete scanned URL history to any script running in user's browser. | Added `verify_history_access` blocking `Sec-Fetch-Site: cross-site` and untrusted origins; sanitized stored URLs. |
| **VULN-05: Disabled TLS Verification** | High | `verify=False` allowed MITM tampering and suppressed legitimate certificate anomalies. | Restored `verify=True`, removed warning suppression, and handled certificate errors safely in degraded mode. |
| **VULN-06: Sensitive Token & Credential Logging** | Medium | Raw URLs containing passwords, tokens, or session IDs were logged and stored unredacted. | Centralized URL sanitization strips credentials and redacts sensitive query parameters across logs and history. |
