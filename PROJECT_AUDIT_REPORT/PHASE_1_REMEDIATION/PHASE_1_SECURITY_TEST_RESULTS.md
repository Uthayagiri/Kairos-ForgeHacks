# Phase 1 Security Test Results & Regression Evidence

**Project:** PhishGuard AI  
**Test Suite:** Backend Pytest Suite (Existing Unit Tests + Phase 1 Security Regressions)  
**Execution Environment:** Windows 11, Python 3.13.14, pytest 9.1.1, anyio 4.15.1, httpx 0.28.1  
**Date:** October 10, 2026  

---

## 1. Test Summary

| Metric | Result |
|---|---|
| **Total Tests Collected** | **105** |
| **Tests Passed** | **105** (100%) |
| **Tests Failed** | **0** (0%) |
| **Tests Skipped** | **0** (0%) |
| **Warnings** | 2 (Starlette `httpx` deprecation notice) |
| **Execution Duration** | ~81 seconds |
| **Status** | **ALL TESTS PASSED** |

---

## 2. Test Execution Commands Actually Executed

```bash
# 1. Verification of new dedicated security regression suite
.\backend\venv\Scripts\python.exe -m pytest tests/test_phase1_security.py -v

# 2. Verification of modified API routes and engine modules
.\backend\venv\Scripts\python.exe -m pytest tests/test_detection_engine.py tests/test_api_predict.py -v

# 3. Full test suite execution across entire backend
.\backend\venv\Scripts\python.exe -m pytest -v
```

---

## 3. Detailed Results by Module

### A. Phase 1 Security Regressions (`tests/test_phase1_security.py`) — 18 Tests Passed

| Test Case | Status | Verified Security Behavior |
|---|---|---|
| `test_ssrf_guard_blocks_private_and_restricted_destinations` | **PASS** | Blocks loopback (`127.0.0.1`), private RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), cloud metadata (`169.254.169.254`), CGNAT (`100.64.0.0/10`), documentation IPs (`192.0.2.0/24`), IPv6 loopback (`::1`), ULA (`fc00::/7`), link-local (`fe80::/10`), and IPv4-mapped IPv6 (`::ffff:127.0.0.1`, `::ffff:169.254.169.254`). |
| `test_ssrf_guard_accepts_clean_public_ips` | **PASS** | Validates legitimate public IPv4 (`8.8.8.8`, `1.1.1.1`, `93.184.216.34`) and public IPv6 (`2606:4700:4700::1111`). |
| `test_ssrf_hostname_multi_dns_rejection` | **PASS** | When a hostname returns multiple DNS `A`/`AAAA` answers where at least one is restricted, the entire request is rejected. |
| `test_ssrf_dns_resolution_failure_handled_gracefully` | **PASS** | DNS resolution errors (`socket.gaierror`) hand over safely to HTTP client connection handlers without uncaught crashes. |
| `test_validate_outbound_url_schemes_and_ports` | **PASS** | Blocks non-web schemes (`ftp:`, `file:`, `gopher:`, `javascript:`) and invalid port numbers (`99999`). Permits clean `https://` with valid port (`8443`). |
| `test_validate_outbound_url_embedded_credentials` | **PASS** | Rejects target URLs containing embedded credentials (`http://admin:secret@example.com`). |
| `test_sanitize_url_for_logging` | **PASS** | Strips user credentials and masks sensitive parameters (`token=[REDACTED]`, `session=[REDACTED]`, `code=[REDACTED]`). |
| `test_sync_fetch_single_html_blocks_redirect_to_private_ip` | **PASS** | A 302 redirect from a public entry URL to `http://192.168.1.100` is blocked before the second request is made. |
| `test_sync_fetch_single_html_blocks_redirect_to_metadata` | **PASS** | A 301 redirect to cloud metadata (`http://169.254.169.254`) is intercepted and rejected before connection. |
| `test_sync_fetch_single_html_redirect_loop_terminates` | **PASS** | Redirect loops terminate cleanly at `MAX_REDIRECT_HOPS` (3) with a controlled error message. |
| `test_sync_fetch_single_html_blocks_redirect_to_unsupported_scheme` | **PASS** | Redirects to `javascript:` or `file:` schemes are blocked. |
| `test_async_fetch_single_html_redirect_revalidation[asyncio]` | **PASS** | Asynchronous fetcher re-validates destination IP and scheme on every redirect hop. |
| `test_async_fetch_single_html_size_cap[asyncio]` | **PASS** | Payloads exceeding `MAX_RESPONSE_BYTES` (2 MB) are truncated and return a controlled size-limit error. |
| `test_tls_verification_failure_is_graceful` | **PASS** | Untrusted / self-signed TLS certificates raise controlled errors, set `is_ssl_err=True`, and trigger degraded risk scoring without crashing. |
| `test_cors_allows_configured_origins_and_denies_unauthorized` | **PASS** | Allowed frontend origin (`http://localhost:5173`) receives CORS header; untrusted origin (`http://malicious-tracker.com`) receives no CORS header. |
| `test_history_cross_site_fetch_rejected` | **PASS** | Browser requests sending `Sec-Fetch-Site: cross-site` to `/api/history` receive HTTP 403 Forbidden. |
| `test_history_unauthorized_origin_rejected` | **PASS** | Cross-origin requests with untrusted `Origin` header to `/api/history` receive HTTP 403 Forbidden. |
| `test_history_records_sanitize_sensitive_url_tokens` | **PASS** | Scans stored in `HistoryService` have credentials stripped and sensitive query params redacted (`token=[REDACTED]`, `session=[REDACTED]`). |

---

### B. Existing Regression Suites — 87 Tests Passed

| Module | Test Count | Status | Notes |
|---|---|---|---|
| `tests/test_api_predict.py` | 19 | **PASS** | REST endpoint schemas, HTTP 422 vs 200, singleton model caching, restricted CORS preflights, SPA shell detection, adversarial payloads. |
| `tests/test_detection_engine.py` | 16 | **PASS** | End-to-end detection orchestration, model loader, degraded mode on timeout/DNS failure, TLS error handling, SPA shell heuristics. |
| `tests/test_url_features.py` | 10 | **PASS** | Lexical feature extraction, IP address detection, `@` symbol obfuscation, subdomains, TLD entropy. |
| `tests/test_html_features.py` | 11 | **PASS** | DOM parsing, password field extraction, external form actions, hidden iframes, meta-refresh redirects. |
| `tests/test_fetch_html.py` | 6 | **PASS** | Live fetch timeout handling, non-200 HTTP statuses, Content-Type enforcement, SSL error simulation. |
| `tests/test_api_enhanced.py` | 4 | **PASS** | Unified `/api/analyze`, history retrieval, summary stats, history purge. |
| `tests/test_build_training_dataset.py` | 4 | **PASS** | Synthetic dataset construction and schema drift protection. |
| `tests/test_crawl_legitimate_deep_links.py` | 4 | **PASS** | Internal link crawling and candidate gathering. |
| `tests/test_stale_model_protection.py` | 3 | **PASS** | Model versioning, mtime drift detection, concurrent thread safety. |
| `tests/test_train_baseline_models.py` | 4 | **PASS** | Model training baselines, CV scoring, feature importance extraction. |
| `tests/test_tune_and_finalize_model.py` | 6 | **PASS** | Hyperparameter tuning, artifact persistence, calibrated inference. |

---

## 4. Tests That Could Not Be Run

- **Real Upstream Metadata Invocations:** In accordance with Safety Rule 7, no real requests were made to cloud metadata endpoints (`169.254.169.254`) or live malicious domains. All SSRF tests used local mock address fixtures and mocked socket responses.
