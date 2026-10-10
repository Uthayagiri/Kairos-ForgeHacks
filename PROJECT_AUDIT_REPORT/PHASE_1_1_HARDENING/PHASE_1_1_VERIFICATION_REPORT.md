# PhishGuard AI — Phase 1.1 Security Verification & Hardening Report

**Audit Phase:** Phase 1.1 Security Verification & Hardening  
**Target System:** PhishGuard AI Backend & Integration Layer  
**Auditor:** Senior Application Security & Systems Engineer  
**Date:** October 10, 2026  
**Status:** Verification Complete — All Findings Resolved & Deterministically Tested

---

## Executive Summary

Following the Phase 1 backend remediation (which resolved high-severity SSRF, event loop starvation, input validation, and model loading issues with 105 passing tests), Phase 1.1 addressed three documented residual risk areas prior to commencing browser extension work:

1. **DNS Rebinding & Connection Validation (TOCTOU Flaw):** Previously, IP validation occurred during pre-flight URL parsing, but subsequent HTTP clients (`requests` / `httpx`) performed independent DNS queries at TCP socket establishment time. This left a Time-of-Check to Time-of-Use window vulnerable to 0-TTL DNS rebinding attacks.
2. **Broad Extension Origin Matching:** The CORS configuration previously relied on an over-permissive wildcard regular expression (`^(chrome|moz)-extension://.*$`) that permitted any installed browser extension to make authenticated cross-origin requests.
3. **Scan History & Telemetry Authentication:** When `REQUIRE_HISTORY_AUTH` was false or an API key was not configured, history endpoints (`/api/history`, `/api/history/clear`, `/api/stats`) permitted unauthenticated reads and purges. Furthermore, checking browser-only headers (`Origin`, `Referer`, `Sec-Fetch-Site`) did not provide authentication for non-browser clients.

All three risk areas have been thoroughly hardened, verified, and backed by 13 new deterministic regression tests. The entire backend test suite now stands at **118 passing tests with 0 failures**.

---

## Finding Status Matrix

| ID | Security Area | Initial Status | Phase 1.1 Status | Remediation Summary |
|---|---|---|---|---|
| **SEC-1.1-01** | DNS Rebinding & Connection Pinning | Residual Risk | **FIXED** | Implemented `SSRFGuardedNetworkBackend`, `SSRFGuardedAsyncTransport`, and `SSRFGuardedSyncAdapter`. DNS is resolved at connection time, every IP is SSRF-validated, and TCP sockets are directly pinned to validated literal IPs while preserving TLS SNI and Host headers. |
| **SEC-1.1-02** | Extension Origin CORS Restriction | Residual Risk | **FIXED** | Replaced open wildcard regex with explicit `ALLOWED_EXTENSION_IDS` allowlist and development-only strict unpacked matching (`^chrome-extension://[a-z]{32}$`). In production, only explicitly configured extension IDs are permitted. |
| **SEC-1.1-03** | History & Telemetry Authentication | Residual Risk | **FIXED** | Implemented an ephemeral in-memory session handshake (`GET /api/auth/token`) and constant-time HMAC comparison for configured `HISTORY_API_KEY`. Unauthenticated requests when auth is enabled receive HTTP 401; invalid keys receive HTTP 403. Dashboard frontend integration preserves legitimate UI functionality without hardcoded secrets. |
| **SEC-1.1-04** | ML Model & Asset Preservation | Unverified | **FIXED (Preserved)** | XGBoost v1.2 model artifacts (`phishing_model.joblib`, `model_metadata.json`), feature extraction pipelines, and calibration parameters remained completely unmodified. |

---

## Detailed Technical Remediation

### 1. DNS Rebinding and Connection Validation

#### Architectural Analysis & Flaw Identification
An ordinary DNS lookup followed by a separate HTTP request does not guarantee that the validated IP is the one contacted. If an attacker controls the authoritative nameserver for `rebind.attacker.com` with a TTL of 0 seconds:
1. `validate_outbound_url()` resolves `rebind.attacker.com` -> `93.184.216.34` (Public IP, check passes).
2. `requests.get()` or `httpx.get()` creates a TCP socket, triggering a second DNS lookup.
3. Attacker nameserver answers with `127.0.0.1` or `169.254.169.254`.
4. The client connects to the internal loopback or cloud metadata endpoint, bypassing the SSRF guard.

#### Vetted Connection-Pinning Implementation
To eliminate this TOCTOU flaw without breaking TLS certificate verification or introducing custom SSL bugs, connection-level pinning was implemented for both asynchronous and synchronous transports:

1. **Async Transport (`SSRFGuardedNetworkBackend` & `SSRFGuardedAsyncTransport`):**
   - Subclassed `httpcore.AnyIOBackend.connect_tcp`.
   - Performs DNS resolution at socket connection time via `socket.getaddrinfo`.
   - Iterates over all returned records (IPv4 and IPv6) and passes them to `is_ip_restricted`. If ANY address belongs to private, loopback, link-local, carrier-grade NAT, or cloud metadata ranges, it immediately raises `httpcore.ConnectError`.
   - Connects the TCP socket directly to the validated literal numeric IP string (`anyio.connect_tcp(remote_host=pinned_ip, remote_port=port)`). This ensures the operating system cannot perform a secondary DNS lookup.
   - Preserves standard TLS SNI: when `httpcore` initiates TLS wrapping (`stream.start_tls`), it passes the original target domain name (`server_hostname=host`). The standard TLS handshake uses the default root CA certificate bundle and verifies the certificate against the server hostname without unsafe TLS alterations.
   - HTTP Host header continues to transmit `Host: host`.

2. **Sync Transport (`SSRFGuardedSyncAdapter` & `SSRFGuardedHTTPConnection` / `SSRFGuardedHTTPSConnection`):**
   - Subclasses `urllib3.connection.HTTPConnection` and `HTTPSConnection._new_conn`.
   - Intercepts socket creation, validates all resolved IP addresses, and establishes the connection directly to `(pinned_ip, port)`.
   - In HTTPS connections, `HTTPSConnection.connect()` invokes standard `_ssl_wrap_socket_and_match_hostname` using `self.host`, ensuring complete TLS SNI validation.
   - Mounted onto `requests.Session` in `DetectionEngine` for `"http://"` and `"https://"`.

3. **Redirect Loop Revalidation:**
   - Redirects are processed manually hop-by-hop with `allow_redirects=False` / `follow_redirects=False`.
   - Each hop URL is structurally validated, and its destination host is re-validated and connection-pinned at socket creation time.
   - Timeout budgets (`self.fetch_timeout`) and response size limits (`self.max_bytes = 2 MB`) are strictly enforced.

---

### 2. Extension Origin Restriction

#### Architectural Analysis & Flaw Identification
In Phase 1, `CORS_ALLOW_ORIGIN_REGEX` was configured as `r"^(chrome-extension|moz-extension)://.*$"`. Any Chromium or Firefox extension with any arbitrary extension ID could initiate cross-origin requests to the FastAPI backend.

#### Configurable Allowlist Implementation
1. **Explicit Production Allowlist (`ALLOWED_EXTENSION_IDS`):**
   - Added `ALLOWED_EXTENSION_IDS: List[str] = []` to `app.core.config.Settings`.
   - In production, operators configure the specific 32-character extension ID published for PhishGuard AI (e.g., via `ALLOWED_EXTENSION_IDS=["kbmfdnhgopbljmjhphkmgfmhhlgchjfl"]`).
   - Extensions not explicitly listed in `ALLOWED_EXTENSION_IDS` or `CORS_ALLOWED_ORIGINS` are rejected during CORS preflight and direct requests.

2. **Development Unpacked Toggle (`ALLOW_DEV_EXTENSION_ORIGINS`):**
   - Manifest V3 extensions loaded in developer mode from disk have dynamically assigned 32-letter IDs matching `^[a-z]{32}$`.
   - When `APP_ENV == "development"` and `ALLOW_DEV_EXTENSION_ORIGINS == True`, CORS permits origins matching `r"^chrome-extension://[a-z]{32}$"`.
   - Wildcards (`.*`), special characters, path traversal (`../../`), and unlisted Firefox extensions are strictly rejected.
   - In production (`APP_ENV != "development"`), `effective_cors_allow_origin_regex` evaluates to `None`, closing all unpacked matching.

3. **Dynamic CORS Evaluation (`DynamicCORSMiddleware`):**
   - Added `DynamicCORSMiddleware` in `backend/app/main.py` overriding `is_allowed_origin` to dynamically evaluate requests against active settings, ensuring origin security is maintained if configuration is reloaded.
   - CORS is strictly decoupled from authentication and authorization.

---

### 3. History & Telemetry Authentication

#### Architectural Analysis & Flaw Identification
Previously:
- If `REQUIRE_HISTORY_AUTH = False`, history and telemetry routes were completely open to unauthenticated access from local tools, curl, or forged requests.
- If `REQUIRE_HISTORY_AUTH = True` but `HISTORY_API_KEY = None`, any non-empty header was accepted.
- Relying on `Sec-Fetch-Site` or `Origin` headers only guarded against cross-site browser fetches, not API consumers or unauthorized access.

#### Ephemeral Session Handshake & HMAC Protection
A robust authentication mechanism was implemented that secures history endpoints without requiring hardcoded secrets in client-side code:

1. **Startup Ephemeral Session Secret:**
   - The backend generates a cryptographically secure 256-bit runtime session token on startup (`secrets.token_urlsafe(32)`).
   - This token is kept in server memory and rotates across application restarts.

2. **Session Handshake Endpoint (`GET /api/auth/token`):**
   - Legitimate web dashboards (running on approved CORS origins like `http://localhost:5173`) call `GET /api/auth/token` on startup.
   - The endpoint strictly rejects cross-site requests (`Sec-Fetch-Site: cross-site` -> HTTP 403) and unauthorized origins.
   - Untrusted third-party web pages cannot obtain this token due to the Same-Origin Policy and strict CORS headers.

3. **Constant-Time Verification (`verify_history_access`):**
   - If `REQUIRE_HISTORY_AUTH` is enabled or running in production (`APP_ENV != "development"`):
     - Requests lacking authentication headers receive **HTTP 401 Unauthorized**.
   - If an authentication header (`X-API-Key` or `Authorization: Bearer <key>`) is provided:
     - Verified using `hmac.compare_digest` against either the configured `HISTORY_API_KEY` (for administrative CLI/scripts) OR the active runtime session token (for the web dashboard).
     - Any invalid key receives **HTTP 403 Forbidden** (even if `REQUIRE_HISTORY_AUTH` is False).
   - Non-browser clients without credentials can no longer access history data when authentication is enforced.

4. **Coordinated Dashboard Client Integration (`frontend/src/api/predictApi.js`):**
   - Added `getSessionAuthHeaders()` to the frontend client.
   - On initial load, the frontend acquires and caches the session token from `/api/auth/token` (or uses `VITE_HISTORY_API_KEY` if configured in the environment).
   - Attaches `X-API-Key` to `fetchHistory()`, `clearBackendHistory()`, and `fetchStats()`.
   - Dashboard functionality continues operating seamlessly on `localhost:5173` without exposing secrets to external origins.

---

## Verification Test Results

Targeted tests were executed in `backend/tests/test_phase1_1_hardening.py`, followed by the full backend regression suite.

- **Phase 1.1 Targeted Hardening Tests:** 13 passed, 0 failed.
- **Phase 1 Security Regression Tests:** 18 passed, 0 failed.
- **Pre-existing Backend Tests:** 87 passed, 0 failed.
- **Total Backend Tests:** **118 passed, 0 failed (100% pass rate).**

For individual test breakdown and execution telemetry, see [PHASE_1_1_TEST_RESULTS.md](file:///c:/Users/Udhaya/S5_Phishing_Detector/PROJECT_AUDIT_REPORT/PHASE_1_1_HARDENING/PHASE_1_1_TEST_RESULTS.md).

---

## Residual Architecture & Operational Recommendations

1. **Production Extension Publishing:**
   - When the Chromium extension is published to the Chrome Web Store, the final 32-character extension ID must be added to `ALLOWED_EXTENSION_IDS` in the production environment variables (`.env`).
   - `ALLOW_DEV_EXTENSION_ORIGINS` must remain disabled in production (`APP_ENV=production`).
2. **Persistent Administrative API Key:**
   - For automated CI/CD monitoring or external SIEM ingestion of `/api/stats`, configure a dedicated high-entropy string in `HISTORY_API_KEY`.
3. **Phase 2 Readiness:**
   - The backend is now fully hardened against SSRF, TOCTOU DNS rebinding, broad CORS abuse, and unauthorized telemetry access.
   - The codebase is ready to proceed to Phase 2 (Browser Extension Blocking & Interception).
