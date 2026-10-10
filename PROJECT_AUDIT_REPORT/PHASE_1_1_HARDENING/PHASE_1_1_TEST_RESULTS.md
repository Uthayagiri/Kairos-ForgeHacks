# PhishGuard AI — Phase 1.1 Test Execution Results

**Environment:** Windows / Python 3.13.14  
**Test Framework:** pytest 9.1.1 with anyio 4.15.1  
**Total Tests Run:** 118  
**Passed:** 118  
**Failed:** 0  
**Pass Rate:** 100.0%  
**Date:** October 10, 2026  

---

## 1. Phase 1.1 Targeted Security Hardening Suite

File: `backend/tests/test_phase1_1_hardening.py`  
Status: **13 / 13 PASSED (100%)**

| Test Function | Verification Scope | Status |
|---|---|---|
| `test_resolve_and_validate_all_ips_ipv4_and_ipv6` | Validates public IPv4 (`93.184.216.34`) and IPv6 (`2606:2800:...`), while rejecting ULA IPv6 (`fd00::1`), mapped loopback (`::ffff:127.0.0.1`), and link-local metadata (`169.254.169.254`). | **PASSED** |
| `test_dns_rebinding_sync_connection_pinning_blocks_private_ip` | Simulates sync DNS rebinding attack where pre-check resolves public IP and socket creation rebinds to `127.0.0.1`. Verifies `SSRFGuardedSyncAdapter` blocks connection. | **PASSED** |
| `test_dns_rebinding_async_connection_pinning_blocks_private_ip[asyncio]` | Simulates async DNS rebinding attack where connection-time DNS rebinds to `169.254.169.254`. Verifies `SSRFGuardedAsyncTransport` intercepts and terminates connection. | **PASSED** |
| `test_ssrf_guarded_backend_pins_socket_to_numeric_ip[asyncio]` | Verifies `SSRFGuardedNetworkBackend` calls `anyio.connect_tcp` with literal numeric IP (`93.184.216.34`) instead of domain, guaranteeing immunity to secondary OS lookups. | **PASSED** |
| `test_cors_denies_unconfigured_extension_in_production` | Confirms that in production mode (`APP_ENV=production`), unlisted extension origins do not receive CORS headers. | **PASSED** |
| `test_cors_allows_explicitly_configured_extension_id` | Verifies explicitly configured extension IDs in `ALLOWED_EXTENSION_IDS` receive CORS approval. | **PASSED** |
| `test_cors_dev_mode_permits_unpacked_32_char_chromium_id` | Verifies dev mode permits standard 32-letter unpacked IDs while rejecting malformed origins, special characters, and wildcards (`*`). | **PASSED** |
| `test_history_unauthenticated_request_rejected_when_auth_required` | Verifies `GET /api/history`, `POST /api/history/clear`, and `GET /api/stats` return HTTP 401 Unauthorized when unauthenticated and auth is enabled. | **PASSED** |
| `test_history_invalid_credentials_rejected_when_auth_required` | Verifies invalid credentials return HTTP 403 Forbidden. | **PASSED** |
| `test_history_authorized_with_configured_api_key` | Verifies requests with valid `X-API-Key` or `Authorization: Bearer` configured keys are authorized (HTTP 200). | **PASSED** |
| `test_history_authorized_with_ephemeral_session_token` | Verifies session handshake (`GET /api/auth/token`) issues tokens that authorize history, stats, and clear operations (HTTP 200). | **PASSED** |
| `test_history_invalid_key_rejected_even_when_require_auth_false` | Verifies forged credentials are rejected with HTTP 403 even when `REQUIRE_HISTORY_AUTH=False`. | **PASSED** |
| `test_session_token_endpoint_blocks_cross_site_and_unauthorized_origin` | Confirms `/api/auth/token` blocks cross-site browser fetches (`Sec-Fetch-Site: cross-site`) and unauthorized origins (HTTP 403). | **PASSED** |

---

## 2. Phase 1 Security Regression Suite

File: `backend/tests/test_phase1_security.py`  
Status: **18 / 18 PASSED (100%)**

- SSRF IP filter coverage (loopback, private, link-local, carrier-grade NAT, 6to4)
- Outbound URL scheme, port, and credential sanitization
- Synchronous and asynchronous redirect guards
- Event loop non-blocking async execution
- ModelLoader SHA256 integrity check and singleton concurrency
- Sensitive token redaction in history records
- Cross-site fetch restrictions

---

## 3. Core Engine & Application Test Suite

Status: **87 / 87 PASSED (100%)**

| Test Module | Test Count | Status | Description |
|---|---|---|---|
| `test_api_predict.py` | 19 | **PASSED** | Route validation, payload contracts, API aliases |
| `test_api_enhanced.py` | 4 | **PASSED** | Health checks, enhanced analysis endpoints, history |
| `test_detection_engine.py` | 16 | **PASSED** | Feature extraction, scoring thresholds, fallbacks |
| `test_html_features.py` | 11 | **PASSED** | DOM element inspection, script and iframe parsing |
| `test_url_features.py` | 10 | **PASSED** | Structural lexical URL features, entropy, symbols |
| `test_fetch_html.py` | 6 | **PASSED** | HTTP client timeout, encoding, body size bounds |
| `test_tune_and_finalize_model.py` | 6 | **PASSED** | Model inference, XGBoost probability calibration |
| `test_train_baseline_models.py` | 4 | **PASSED** | Model training reproducibility and accuracy metrics |
| `test_build_training_dataset.py` | 4 | **PASSED** | Dataset ingestion and schema verification |
| `test_crawl_legitimate_deep_links.py` | 4 | **PASSED** | Deep link crawl validation |
| `test_stale_model_protection.py` | 3 | **PASSED** | Stale model artifact detection and rejection |

---

## 4. Aggregate Test Execution Summary

```
============================= test session starts =============================
platform win32 -- Python 3.13.14, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\Udhaya\S5_Phishing_Detector\backend
plugins: anyio-4.15.1
collected 118 items

tests\test_api_enhanced.py ....                                          [  3%]
tests\test_api_predict.py ...................                            [ 19%]
tests\test_build_training_dataset.py ....                                [ 22%]
tests\test_crawl_legitimate_deep_links.py ....                           [ 26%]
tests\test_detection_engine.py ................                          [ 39%]
tests\test_fetch_html.py ......                                          [ 44%]
tests\test_html_features.py ...........                                  [ 54%]
tests\test_phase1_1_hardening.py .............                           [ 65%]
tests\test_phase1_security.py ..................                         [ 80%]
tests\test_stale_model_protection.py ...                                 [ 83%]
tests\test_train_baseline_models.py ....                                 [ 86%]
tests\test_tune_and_finalize_model.py ......                             [ 91%]
tests\test_url_features.py ..........                                    [100%]

============================== warnings summary ===============================
...
================= 118 passed, 2 warnings in 82.75s (0:01:22) ==================
```

---

## 5. Conclusion

All 118 tests passed cleanly without modifying the ML models, altering training pipelines, or breaking backward compatibility. The Phase 1.1 hardening requirements have been fully verified and documented.
