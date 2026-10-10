# Phase 1 Remaining Risks and Future Remediation Roadmap

**Project:** PhishGuard AI  
**Phase:** Phase 1 Post-Remediation Assessment  
**Date:** October 10, 2026  
**Auditor / Engineer:** Senior Backend Security Engineer  

---

## 1. Executive Summary of Post-Remediation Posture

Phase 1 focused strictly on **high-priority backend security remediation** without altering ML models, changing public API response schemas, or modifying frontend/extension code. 

Critical vulnerabilities identified in the audit—namely **SSRF redirect bypasses**, **event loop blocking operations**, **unrestricted wildcard CORS**, **unauthorized cross-site scan history harvesting**, **disabled TLS verification**, and **sensitive token leakage in logs**—have been remediated and verified with regression tests.

However, several residual architectural and operational risks remain that require subsequent remediation phases.

---

## 2. Detailed Remaining Risks & Architectural Boundaries

### A. Residual DNS Rebinding Risk (Time-of-Check vs. Time-of-Use)
- **Description:** Pre-connection URL validation resolves a hostname via `socket.getaddrinfo()` and checks the resulting IP addresses. However, when the underlying HTTP client (`requests` or `httpx`) connects to the host, it may perform a separate DNS lookup if the operating system or connection pool re-resolves the name. An adversary operating a malicious authoritative DNS server with an ultra-low TTL (e.g., 0 seconds) could theoretically return a public IP on the initial lookup and an internal IP (`127.0.0.1` or `169.254.169.254`) on the actual TCP connection.
- **Why It Was Not Completely Solved in Phase 1:** Standard Python HTTP clients (`requests`, `urllib3`, `httpx`) do not natively support pinned-IP connection pooling with preserved SNI/Host headers without custom transport adapters (e.g., custom `urllib3.connectionpool` subclasses or low-level socket overrides). Modifying transports at that depth carries potential connection compatibility side-effects across differing environments.
- **Current Mitigations in Place:**
  - Strict host validation and RFC network blocks on all initial and redirect hops.
  - Multi-IP DNS evaluation (if *any* answer in the set is private, the host is rejected).
  - Short timeout windows (connect timeout capped at 4.0s).
- **Recommended Phase 2 Action:** Implement a custom `httpx.AsyncHTTPTransport` using a custom socket factory or custom DNS resolver cache that pins the validated IP address directly to the connection socket while preserving the TLS SNI hostname.

---

### B. In-Memory Session History Storage
- **Description:** Scan records in `HistoryService` remain stored in memory (bounded to a deque of 200 records). 
- **Limitations:**
  1. Scan history is lost on process restart.
  2. In multi-worker deployments (e.g., Gunicorn/Uvicorn with `--workers > 1`), history records are fragmented across worker processes.
- **Recommended Phase 2 Action:** Transition `HistoryService` to an encrypted SQLite database or persistent Redis cache with tenant separation and optional TTL eviction.

---

### C. Extension Origin Verification Boundary
- **Description:** Chromium Manifest V3 extensions generate extension IDs dynamically upon unpacked loading (e.g., `chrome-extension://<id>`). To prevent breaking local developer extension instances, CORS allows origins matching `^(chrome|moz)-extension://.*$`.
- **Limitation:** Any browser extension installed in the user's browser could theoretically issue cross-origin requests to `http://localhost:8000/predict`. (Note: `/api/history` is guarded against cross-site browser fetches).
- **Recommended Phase 2 Action:** When publishing the extension to the Chrome Web Store, lock the extension ID to a fixed public key, and restrict the CORS regex to only that specific production extension ID.

---

### D. Single-User / Local-Session Architecture
- **Description:** The system currently operates as a local personal security scanner without user accounts, JWT sessions, or multi-tenant database partitioning.
- **Current Mitigation:** Phase 1 added `verify_history_access` which blocks cross-site browser requests (`Sec-Fetch-Site: cross-site`) and unauthorized origins, while optionally supporting `REQUIRE_HISTORY_AUTH=True` with a pre-shared API key (`X-API-Key`).
- **Recommended Phase 2 Action:** If PhishGuard AI is ever deployed as a shared multi-user cloud service (rather than a localhost tool), integrate FastAPI OAuth2 / JWT authentication with user ownership of scan records.

---

### E. Rate Limiting on Outbound Analysis
- **Description:** Currently, there is no application-level rate limiter on `/api/analyze` or `/predict`.
- **Risk:** An automated client or loop could flood the backend with URLs to scan, consuming local outbound sockets.
- **Recommended Phase 2 Action:** Add an IP-based or client token bucket rate limiter (e.g., `slowapi`) limiting analysis to 30 requests/minute per client.

---

## 3. Verified Safety Invariants

Before concluding Phase 1, the following project integrity checks were performed:

1. **Production ML Model Untouched:**
   - File `backend/ml/models/phishing_model.joblib`: **UNMODIFIED** (hash and mtime preserved).
   - File `backend/ml/models/model_metadata.json`: **UNMODIFIED**.
   - Model feature count (43 features) and threshold logic: **UNMODIFIED**.

2. **Frontend UI & Browser Extension Untouched:**
   - All files under `frontend/`: **UNMODIFIED**.
   - All files under `extension/`: **UNMODIFIED**.

3. **No Secret Tokens in Source Control:**
   - No API keys, passwords, or cloud credentials were added.
   - Tested and verified URL sanitization prevents user tokens from entering server logs.

4. **TLS Certificate Verification Enabled:**
   - No `verify=False` remains in the codebase.
   - Self-signed and invalid certificates trigger safe degraded-mode indicators without application failure.

5. **Test Suite Health:**
   - Full test suite passes: **105 passed, 0 failed, 0 skipped**.
