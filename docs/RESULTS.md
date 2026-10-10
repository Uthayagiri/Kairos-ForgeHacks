# PhishGuard AI — Experimental Results & Model Evaluation

This document details the quantitative evaluation metrics, cross-validation stability, confusion matrix breakdown, probability calibration analysis, inference latency benchmarks, and 50-URL unseen benchmark results for **PhishGuard AI** (Production Model Version `2.1.0` — Candidate A4).

---

## 1. Full Metric Suite: Legacy v1.0 vs. Rejected v2.0 vs. Candidate A4 (Clean Domain Split)

All metrics below were evaluated on the **exact same 1,799-sample held-out domain-grouped test set** (1,402 Legitimate, 397 Phishing across 631 unique domains with **0.00% domain overlap leakage**):

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                        FULL METRIC SUITE COMPARISON ON CLEAN DOMAIN SPLIT                              │
├──────────────────────────────┬───────────────────┬───────────────────┬───────────────────┬─────────────┤
│ Metric                       │ Legacy Baseline   │ Rejected v2.0     │ Balanced Champion │ Target /    │
│                              │ v1.0 (Deployed)   │ (Calibrated d3)   │ Candidate A4 (Now)│ Acceptable  │
├──────────────────────────────┼───────────────────┼───────────────────┼───────────────────┼─────────────┤
│ Accuracy                     │ 0.9661 (96.61%)   │ 0.9294 (92.94%)   │ 0.9455 (94.55%)   │ > 94.0%     │
│ Precision                    │ 0.8836 (88.36%)   │ 0.8169 (81.69%)   │ 0.8330 (83.30%)   │ > 82.0%     │
│ Recall (Sensitivity)         │ 0.9748 (97.48%)   │ 0.8766 (87.66%)   │ 0.9421 (94.21%)   │ ~94% - 97%  │
│ False Negatives (Missed)     │ 10 / 397 (2.5%)   │ 49 / 397 (12.3%)  │ 23 / 397 (5.8%)   │ < 25 missed │
│ F1-Score                     │ 0.9269 (92.69%)   │ 0.8457 (84.57%)   │ 0.8842 (88.42%)   │ > 88.0%     │
│ ROC-AUC                      │ 0.9960 (99.60%)   │ 0.9734 (97.34%)   │ 0.9819 (98.19%)   │ > 0.980     │
│ Brier Score Loss             │ 0.0253            │ 0.0518            │ 0.0390            │ < 0.040     │
├──────────────────────────────┼───────────────────┼───────────────────┼───────────────────┼─────────────┤
│ Top-2 Feature Concentration  │ 59.26%            │ 38.04%            │ 43.06% (▼ 16.2%)  │ < 45.0%     │
│ Top 2 Features               │ num_links (48.6%) │ num_int_links(22%)│ num_links (26.5%) │ Balanced    │
│                              │ num_int_links(11%)│ num_links (16%)   │ num_int_links(16.6│ DOM weights │
├──────────────────────────────┼───────────────────┼───────────────────┼───────────────────┼─────────────┤
│ 50-URL Benchmark Attacks     │ 10 / 10 (100%)    │ 10 / 10 (100%)    │ 10 / 10 (100%)    │ 10 / 10     │
│ Clean Legitimate Pass Rate   │ 31 / 34 (9.5% avg)│ 31 / 34 (8.4% avg)│ 31 / 34 (10.9% avg│ Clean pass  │
│ ps.bitsathy.ac.in Raw Score  │ 81.90% (High Phish│ 52.30%            │ 65.43% (Raw Score)│ < 70%       │
├──────────────────────────────┼───────────────────┼───────────────────┼───────────────────┼─────────────┤
│ Single-Request Latency       │ 10.56 ms          │ 61.52 ms (5.8x)   │ 9.89 ms (Native)  │ < 15.0 ms   │
└──────────────────────────────┴───────────────────┴───────────────────┴───────────────────┴─────────────┘
```

---

## 2. Confusion Matrix Breakdown (Clean Domain Split)

### 2.1 Production Candidate A4 (v2.1.0 Deployed)
```
                      ACTUAL CLASS
                  Legitimate    Phishing
               ┌─────────────┬─────────────┐
  PREDICTED    │   TN = 1327 │    FN = 23  │
  Legitimate   │   (94.65%)  │    (5.79%)  │
               ├─────────────┼─────────────┤
  PREDICTED    │    FP = 75  │   TP = 374  │
  Phishing     │    (5.35%)  │   (94.21%)  │
               └─────────────┴─────────────┘
```

### 2.2 Comparison with Prior Versions:
- **Legacy v1.0 Baseline:** TN = 1,351 (96.36%), FP = 51 (3.64%), FN = 10 (2.52%), TP = 387 (97.48%).
- **Rejected v2.0 Calibrated:** TN = 1,323 (94.37%), FP = 79 (5.63%), FN = 49 (12.34%), TP = 348 (87.66%).
- **Candidate A4 Recovery:** Recovers **26 of the 49 false negatives** from rejected v2.0, lifting recall from **87.66% up to 94.21%** (only 23 missed attacks out of 397) while maintaining high precision (83.30%).

---

## 3. Calibration Quality, Brier Score & Risk Score Semantics

### 3.1 Honest Assessment of the Calibration-Recall Tradeoff
- **Brier Score Comparison:** Legacy v1.0 = **0.0253**, Rejected v2.0 = **0.0518**, Candidate A4 = **0.0390**.
- **Important Disclosure:** Candidate A4 intentionally employs aggressive positive class re-weighting (`scale_pos_weight = 5.0`) to prioritize cybersecurity attack recall (94.21%) and minimize dangerous false negatives. Consequently, Candidate A4 **does not** resolve the raw probability miscalibration finding; against v1.0, its Brier score (0.0390) is worse than v1.0's (0.0253).
- **Semantics of Displayed Confidence:** The model output score must be interpreted as a **Monotonic Risk Score / Ordinal Threat Ranking** (where higher values indicate stronger threat signals and higher review priority), rather than a literal calibrated posterior empirical probability.

---

## 4. Top 15 Feature Importances (Production Model v2.1.0)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│          TOP 15 FEATURE IMPORTANCES — PRODUCTION XGBOOST (v2.1.0)           │
├─────┬────────────────────────────────────┬────────────┬──────────┬──────────┤
│ Rnk │ Feature Name                       │ Importance │ Percent  │ Type     │
├─────┼────────────────────────────────────┼────────────┼──────────┼──────────┤
│  1  │ num_links                          │ 0.264683   │ 26.47%   │ HTML/DOM │
│  2  │ num_internal_links                 │ 0.165939   │ 16.59%   │ HTML/DOM │
│  3  │ num_external_links                 │ 0.065388   │  6.54%   │ HTML/DOM │
│  4  │ domain_length                      │ 0.048038   │  4.80%   │ URL      │
│  5  │ uses_https                         │ 0.035790   │  3.58%   │ URL      │
│  6  │ external_link_ratio                │ 0.030348   │  3.03%   │ HTML/DOM │
│  7  │ path_length                        │ 0.025519   │  2.55%   │ URL      │
│  8  │ num_digits                         │ 0.023485   │  2.35%   │ URL      │
│  9  │ num_subdomains                     │ 0.023429   │  2.34%   │ URL      │
│ 10  │ num_images                         │ 0.022757   │  2.28%   │ HTML/DOM │
│ 11  │ has_ip_address                     │ 0.022510   │  2.25%   │ URL      │
│ 12  │ num_forms                          │ 0.020815   │  2.08%   │ HTML/DOM │
│ 13  │ num_slashes                        │ 0.020478   │  2.05%   │ URL      │
│ 14  │ has_form_action_empty_or_javascript│ 0.019812   │  1.98%   │ HTML/DOM │
│ 15  │ has_suspicious_keywords            │ 0.018940   │  1.89%   │ URL      │
├─────┼────────────────────────────────────┼────────────┼──────────┼──────────┤
│     │ TOP 2 FEATURE CONCENTRATION        │ 0.430622   │ 43.06%   │ (▼ 16.2%)│
└─────┴────────────────────────────────────┴────────────┴──────────┴──────────┘
```

---

## 5. 50-URL Unseen Benchmark Evaluation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 50-URL UNSEEN REAL-WORLD BENCHMARK SUMMARY                  │
├─────────────────────────────────────────┬──────────────┬────────────────────┤
│ Category / Test Scope                   │ Result       │ Performance Detail │
├─────────────────────────────────────────┼──────────────┼────────────────────┤
│ Phishing Attacks Caught (Category 5)    │ 10 / 10      │ 100.0% (0 FN)      │
│ Clean Legitimate URLs (HTTP 200)        │ 31 / 34      │ 10.9% Mean Score   │
│ WAF-Challenged Sites (Cloudflare 403)   │  8 / 8       │ Protected by Engine│
└─────────────────────────────────────────┴──────────────┴────────────────────┘
```

### Case Study: `https://ps.bitsathy.ac.in`
- **Legacy v1.0 Raw Score:** **81.90%** (Severe False Phishing Threat)
- **Candidate A4 Raw Score:** **65.43%** (Raw booster output before detection engine dampening)
- **Full Engine Risk Assessment:** Under the complete Detection Engine architecture, the structural SPA detection branch intercepts the unrendered client-side shell and bounds the user-facing risk level to **Medium/Suspicious** with clear explanatory messaging.

---

## 6. Single-Request Inference Latency

Measured across **500 single-request runs** using monotonic high-resolution timing:
- **Legacy Baseline v1 (Single Booster):** 10.56 ms
- **Rejected v2.0 (Calibrated 5x Ensemble):** 61.52 ms
- **Production Candidate A4 (Native Booster):** **9.89 ms** (Fast, zero ensemble overhead)

---

## 7. Extended Generalization & Test Suite Verifications

### 7.1 Unseen Auth-Portal Benchmark Suite

Evaluated across 6 representative enterprise single sign-on and authentication portals:

| Target Auth Portal | Verdict | Risk Level | Score | `has_login_form` | `num_links` | Architectural Evaluation Criterion |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `https://auth0.com` | `safe` | Low Risk | 0.30% | `False` | 234 | Standard rich portal $\rightarrow$ `is_likely_unrendered_spa_shell = False` (Safe pass) |
| `https://signin.aws.amazon.com` | `safe` | Low Risk | 0.80% | `False` | 145 | Standard rich portal $\rightarrow$ `is_likely_unrendered_spa_shell = False` (Safe pass) |
| `https://github.com/login` | `safe` | Low Risk | 24.60% | `True` | 11 | Static login form present $\rightarrow$ SPA dampening blocked $\rightarrow$ Base model classifies as Safe |
| `https://gitlab.com/users/sign_in` | `safe` | Low Risk | 20.80% | `N/A` | `N/A` | WAF HTTP 403 $\rightarrow$ Degraded URL-only mode classifies as Safe |
| `https://id.atlassian.com/login` | `suspicious` | Medium Risk | 42.68% | `False` | 0 | Minimal unrendered SPA shell $\rightarrow$ `is_likely_unrendered_spa_shell = True` (Dampened to Medium) |
| `https://login.microsoftonline.com` | `suspicious` | Medium Risk | 48.00% | `False` | 0 | Minimal unrendered SPA shell $\rightarrow$ `is_likely_unrendered_spa_shell = True` (Dampened to Medium) |
| `https://login.salesforce.com` | `phishing` | High Risk | 82.20% | `True` | 8 | Static login form present $\rightarrow$ SPA dampening blocked $\rightarrow$ Flagged on keyword/form weights |

- **Quantified Architectural Branch Compliance:** **7 / 7 portals (100%)** adhered strictly to their intended architectural branch (0 unexpected SPA dampening bypasses; 0 static form false dampening breaches).

## 8. Controlled `scale_pos_weight` Experiment (Current Production vs. Candidate A vs. Candidate B)

To scientifically isolate the effect of positive class weighting (`scale_pos_weight`), a controlled experiment was executed under **strictly identical training conditions** (same 8,910 dataset, same 43 features, same domain-grouped 80/20 train/test split, same hyperparameter configuration: `max_depth=4`, `learning_rate=0.05`, `n_estimators=200`, `colsample_bytree=0.7`, `subsample=0.95`, `reg_lambda=1.0`, `random_state=42`).

### 8.1 Model Artifact Identifiers & Hashes
- **Current Production (`scale_pos_weight = 5.0`):**
  - Path: `backend/ml/models/phishing_model.joblib`
  - SHA256: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`
  - Size: 321,430 bytes | Modified: 2026-09-08
- **Candidate A (`scale_pos_weight = 3.5`):**
  - Path: `backend/ml/models/candidates_spw/candidate_a_spw3.5.joblib`
  - SHA256: `5119cfb0fd03386d4562198211425b2da66398b3d5d6f21f22ff3625a10eb8d0`
  - Size: 319,530 bytes | Modified: 2026-09-08
- **Candidate B (`scale_pos_weight = 4.0`):**
  - Path: `backend/ml/models/candidates_spw/candidate_b_spw4.0.joblib`
  - SHA256: `8d4621c280919d42564f17b2abf9ad0e6654ba17d93408e0207cbe0aeb477f74`
  - Size: 319,458 bytes | Modified: 2026-09-08

### 8.2 Test Set Metric Comparison (1,799 Held-Out Domain-Split Samples)

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│               TEST SET PERFORMANCE COMPARISON (1,799 Held-Out Domain-Split Samples)                    │
├──────────────────────────────┬───────────────────┬───────────────────┬───────────────────┬─────────────┤
│ Metric                       │ Current Production│ Candidate A       │ Candidate B       │ Target /    │
│                              │ (spw = 5.0)       │ (spw = 3.5)       │ (spw = 4.0)       │ Floor       │
├──────────────────────────────┼───────────────────┼───────────────────┼───────────────────┼─────────────┤
│ Accuracy                     │ 94.55%            │ 95.16%            │ 94.94%            │ > 94.0%     │
│ Precision                    │ 83.30%            │ 86.56%            │ 85.58%            │ > 82.0%     │
│ Phishing Recall              │ 94.21% (374/397)  │ 92.44% (367/397)  │ 92.70% (368/397)  │ >= 94.0%    │
│ False Negatives (Missed)     │ 23 missed (5.79%) │ 30 missed (7.56%) │ 29 missed (7.30%) │ <= 25 missed│
│ False Positives (False Alarm)│ 75 (5.35% FPR)    │ 57 (4.07% FPR)    │ 62 (4.42% FPR)    │ Lower = Good│
│ True Negatives               │ 1327 / 1402       │ 1345 / 1402       │ 1340 / 1402       │ -           │
│ F1-Score                     │ 88.42%            │ 89.40%            │ 89.00%            │ > 88.0%     │
│ ROC-AUC                      │ 0.9819            │ 0.9806            │ 0.9814            │ > 0.980     │
│ Brier Score Loss             │ 0.0390            │ 0.0363            │ 0.0368            │ < 0.040     │
│ Top-2 Feature Concentration  │ 43.06%            │ 43.52%            │ 43.58%            │ < 45.0%     │
│ Recall Floor Status          │ PASS (>= 94.0%)   │ FAIL (92.44%)     │ FAIL (92.70%)     │ >= 94.0%    │
└──────────────────────────────┴───────────────────┴───────────────────┴───────────────────┴─────────────┘
```

### 8.3 Real-World Legitimate Benchmark Side-by-Side Comparison

| Target Site & Context | Production (5.0) Raw | Production (5.0) Final | Candidate A (3.5) Raw | Candidate A (3.5) Final | Candidate B (4.0) Raw | Candidate B (4.0) Final |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **College Portal** (`https://ps.bitsathy.ac.in`) | 65.43% | **35.99% (Medium)** | 52.94% | 29.11% (Low) | 57.49% | 31.62% (Medium) |
| **YouTube Video SPA** (`https://www.youtube.com/...`) | 61.12% | **33.62% (Medium)** | 62.12% | 34.16% (Medium) | 65.05% | 35.78% (Medium) |
| **TinyURL Web App** (`https://tinyurl.com/app`) | 58.33% | **32.08% (Medium)** | 45.36% | 24.95% (Low) | 52.71% | 28.99% (Low) |
| **Google SSO** (`https://accounts.google.com`) | 86.50% | **86.50% (High)** | 84.94% | 84.94% (High) | 87.79% | 87.79% (High) |
| **Microsoft Online SSO** (`https://login.microsoftonline.com`) | 87.32% | **48.00% (Medium)** | 85.12% | 46.82% (Medium) | 87.87% | 48.00% (Medium) |
| **Atlassian ID SSO** (`https://id.atlassian.com/login`) | 77.60% | **42.68% (Medium)** | 74.07% | 40.74% (Medium) | 74.87% | 41.18% (Medium) |
| **Salesforce Login** (`https://login.salesforce.com`) | 82.22% | **82.22% (High)** | 73.56% | 73.56% (High) | 71.43% | 71.43% (High) |
| **Auth0 Platform** (`https://auth0.com`) | 0.32% | **0.32% (Low)** | 0.18% | 0.18% (Low) | 0.20% | 0.20% (Low) |
| **AWS Signin** (`https://signin.aws.amazon.com`) | 0.81% | **0.81% (Low)** | 0.85% | 0.85% (Low) | 0.85% | 0.85% (Low) |
| **GitHub Login** (`https://github.com/login`) | 24.56% | **24.56% (Low)** | 16.94% | 16.94% (Low) | 22.14% | 22.14% (Low) |
| **GitLab Signin** (`https://gitlab.com/users/sign_in`) | 37.78% | **20.78% (Low)** | 30.56% | 20.00% (Low) | 33.52% | 20.00% (Low) |
| **Wikipedia Content** (`https://en.wikipedia.org/...`) | 0.43% | **0.43% (Low)** | 0.32% | 0.32% (Low) | 0.40% | 0.40% (Low) |

### 8.4 Real-World Phishing Benchmark Side-by-Side Comparison

| Phishing Attack Pattern | Production (5.0) Raw | Production (5.0) Final | Candidate A (3.5) Raw | Candidate A (3.5) Final | Candidate B (4.0) Raw | Candidate B (4.0) Final |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Raw IP PayPal Phishing** | 92.88% | **92.88% (High)** | 90.88% | 90.88% (High) | 90.04% | 90.04% (High) |
| **Suspicious TLD + Multi-Brand** | 99.77% | **99.77% (High)** | 99.65% | 99.65% (High) | 99.68% | 99.68% (High) |
| **Suspicious TLD Brand Spoof** | 99.88% | **99.88% (High)** | 99.85% | 99.85% (High) | 99.84% | 99.84% (High) |
| **Excessive Subdomains + Phish Path**| 98.72% | **98.72% (High)** | 97.51% | 97.51% (High) | 98.11% | 98.11% (High) |
| **Raw IP Netflix Lure** | 84.87% | **84.87% (High)** | 79.75% | 79.75% (High) | 77.64% | 77.64% (High) |
| **DGA / Brand Spoofing** | 99.56% | **99.56% (High)** | 99.31% | 99.31% (High) | 99.38% | 99.38% (High) |
| **Suspicious TLD Social Lure** | 99.56% | **99.56% (High)** | 99.36% | 99.36% (High) | 99.36% | 99.36% (High) |
| **Crypto Phishing Seed** | 99.31% | **99.31% (High)** | 99.10% | 99.10% (High) | 99.10% | 99.10% (High) |
| **Banking Phishing Lure** | 98.66% | **98.66% (High)** | 98.25% | 98.25% (High) | 98.72% | 98.72% (High) |
| **Government Tax Refund Lure** | 98.75% | **98.75% (High)** | 98.25% | 98.25% (High) | 98.62% | 98.62% (High) |

### 8.5 Single-Request Inference Latency (500 Runs Each)

| Model Artifact | Mean Latency | Median (P50) | P95 Latency | P99 Latency |
| :--- | :--- | :--- | :--- | :--- |
| **Current Production (`spw = 5.0`)** | 10.592 ms | 10.201 ms | 14.172 ms | 16.622 ms |
| **Candidate A (`spw = 3.5`)** | 10.458 ms | 10.130 ms | 12.890 ms | 14.804 ms |
| **Candidate B (`spw = 4.0`)** | 10.838 ms | 10.227 ms | 14.595 ms | 18.547 ms |

### 8.6 Determinism Verification (5 Consecutive Runs Each)

- **Target: College Portal (`https://ps.bitsathy.ac.in`):**
  - Current Production (`spw = 5.0`): `[35.99%, 35.99%, 35.99%, 35.99%, 35.99%]` (Deterministic: **True**)
  - Candidate A (`spw = 3.5`): `[29.11%, 29.11%, 29.11%, 29.11%, 29.11%]` (Deterministic: **True**)
  - Candidate B (`spw = 4.0`): `[31.62%, 31.62%, 31.62%, 31.62%, 31.62%]` (Deterministic: **True**)
- **Target: Google SSO (`https://accounts.google.com`):**
  - Current Production (`spw = 5.0`): `[86.50%, 86.50%, 86.50%, 86.50%, 86.50%]` (Deterministic: **True**)
  - Candidate A (`spw = 3.5`): `[84.94%, 84.94%, 84.94%, 84.94%, 84.94%]` (Deterministic: **True**)
  - Candidate B (`spw = 4.0`): `[87.79%, 87.79%, 87.79%, 87.79%, 87.79%]` (Deterministic: **True**)

---

## 9. Comprehensive Automated Test Suite Execution Summary

All test suites were executed on the active system state with the following confirmed results:

- **Backend Pytest Unit Suite (`pytest tests/`):** **83 / 83 Passed** in 16.75s (100% pass rate)
  - Includes dedicated `test_stale_model_protection.py` (stale artifact auto-reload, concurrent 8-thread safety, and `/model/info` validation).
- **Chrome Extension Verification Suite (`node scratch/verify_extension.js`):** **89 / 89 Passed** (100% pass rate)
  - Validates Manifest V3 compliance, background service worker, popup UI DOM, icons, and live backend contract.
- **Full E2E Integration Suite (`node scratch/test_e2e_integration_full.js`):** **54 / 54 Passed** (100% pass rate)
  - Validates live root, health check, active model hash integrity, legitimate URL scans, phishing attacks, degraded mode, validation errors, and React frontend dev server on port 5173.

---

## 10. Research Phase: Legitimate Auth / SSO / Institutional Portals Investigation

### 10.1 Evaluated Model Artifacts & Hashes
- **Current Production (Control Group):**
  - Path: `backend/ml/models/phishing_model.joblib`
  - SHA256: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`
  - Features: 43 features | Training Samples: 7,111 (`scale_pos_weight = 5.0`)
- **Experimental Model 1 (`+is_institutional_domain`):**
  - Path: `backend/ml/models/candidates_auth/candidate_exp1_inst_feature.joblib`
  - SHA256: `ee2bcb883400c98965da4d48812a8ba2a0071a41b72f58d3b8e5b0a9531e6391`
  - Features: 44 features | Training Samples: 7,111 (`scale_pos_weight = 5.0`)
- **Experimental Model 2 (Targeted Sparse/Auth Data Augmentation):**
  - Path: `backend/ml/models/candidates_auth/candidate_exp2_aug_data.joblib`
  - SHA256: `95a3418cc15273fccd8abadebb6b9ceb7465be3b32a23ad764d69cc754099bca`
  - Features: 43 features | Training Samples: 7,411 (`scale_pos_weight = 5.0`)

### 10.2 Held-Out Domain-Split Test Evaluation (1,799 Samples, 0.00% Domain Leakage)

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                        CLEAN HELD-OUT TEST DOMAIN SPLIT EVALUATION (1,799 Samples)                     │
├──────────────────────────────┬───────────────────┬───────────────────┬───────────────────┬─────────────┤
│ Metric                       │ Current Production│ Experimental M1   │ Experimental M2   │ Target /    │
│                              │ (Control)         │ (+inst_domain)    │ (Data Aug)        │ Floor       │
├──────────────────────────────┼───────────────────┼───────────────────┼───────────────────┼─────────────┤
│ Accuracy                     │ 94.55%            │ 95.11%            │ 94.50%            │ > 94.0%     │
│ Precision                    │ 83.30%            │ 85.52%            │ 84.49%            │ > 82.0%     │
│ Phishing Recall              │ 94.21% (374/397)  │ 93.70% (372/397)  │ 91.94% (365/397)  │ >= 94.0%    │
│ False Negatives (Missed)     │ 23 missed (5.79%) │ 25 missed (6.30%) │ 32 missed (8.06%) │ <= 25 missed│
│ False Positives (False Alarm)│ 75 (5.35% FPR)    │ 63 (4.49% FPR)    │ 67 (4.78% FPR)    │ Lower = Good│
│ F1-Score                     │ 88.42%            │ 89.42%            │ 88.06%            │ > 88.0%     │
│ ROC-AUC                      │ 0.9819            │ 0.9834            │ 0.9809            │ > 0.980     │
│ Brier Score Loss             │ 0.0390            │ 0.0363            │ 0.0392            │ < 0.040     │
│ Top-2 Feature Concentration  │ 43.06%            │ 41.77%            │ 34.95%            │ < 45.0%     │
│ Recall Floor Status          │ PASS (>= 94.0%)   │ FAIL (93.70%)     │ FAIL (91.94%)     │ >= 94.0%    │
└──────────────────────────────┴───────────────────┴───────────────────┴───────────────────┴─────────────┘
```

### 10.3 Real-World Benchmark Three-Way Comparison

| Target Site & Benchmark Category | Production Control (Raw / Final) | Experimental M1 (Raw / Final) | Experimental M2 (Raw / Final) |
| :--- | :--- | :--- | :--- |
| **Bannari Amman College Portal** `[Diagnostic / SPA]` | 65.43% / **35.99% (Med)** | 9.79% / **20.00% (Low)** | 63.02% / **34.66% (Med)** |
| **Google Accounts Login** `[Diagnostic / Auth]` | 86.50% / **86.50% (High)** | 88.65% / **88.65% (High)** | 76.87% / **76.87% (High)** |
| **Salesforce Customer Portal** `[Diagnostic / Auth]` | 82.22% / **82.22% (High)** | 80.27% / **80.27% (High)** | 62.99% / **62.99% (Med)** |
| **TinyURL Web App** `[Diagnostic / Shortener]` | 58.33% / **32.08% (Med)** | 57.54% / **31.65% (Med)** | 50.19% / **27.61% (Low)** |
| **Microsoft Online Entra ID** `[Diagnostic / SPA Auth]` | 87.32% / **48.00% (Med)** | 88.40% / **48.00% (Med)** | 83.05% / **45.68% (Med)** |
| **Atlassian Cloud ID SSO** `[Diagnostic / SPA Auth]` | 77.60% / **42.68% (Med)** | 84.29% / **46.36% (Med)** | 48.52% / **26.69% (Low)** |
| **Harvard Canvas Portal** `[Institutional / University]` | 67.47% / **67.47% (Med)** | 5.04% / **5.04% (Low)** | 53.00% / **53.00% (Med)** |
| **Stanford WebLogin SSO** `[Institutional / University]` | 81.83% / **81.83% (High)** | 40.82% / **40.82% (Med)** | 79.15% / **79.15% (High)** |
| **UC Berkeley CalNet SSO** `[Institutional / University]` | 75.61% / **41.58% (Med)** | 32.63% / **20.00% (Low)** | 71.36% / **39.25% (Med)** |
| **IIT Madras SSO Portal** `[Institutional / University]` | 24.95% / **20.00% (Low)** | 10.96% / **20.00% (Low)** | 43.87% / **24.13% (Low)** |
| **MIT WebSIS Student Portal** `[Institutional / University]` | 33.40% / **20.00% (Low)** | 11.48% / **20.00% (Low)** | 49.02% / **26.96% (Low)** |
| **Oxford University SSO** `[Institutional / University]` | 11.94% / **20.00% (Low)** | 7.04% / **20.00% (Low)** | 22.00% / **20.00% (Low)** |
| **UCLA Student Portal** `[Institutional / University]` | 0.64% / **0.64% (Low)** | 0.26% / **0.26% (Low)** | 0.52% / **0.52% (Low)** |
| **Auth0 Platform Portal** `[Enterprise Identity / SSO]` | 0.32% / **0.32% (Low)** | 0.29% / **0.29% (Low)** | 0.27% / **0.27% (Low)** |
| **AWS Management Console** `[Enterprise Identity / SSO]` | 0.81% / **0.81% (Low)** | 1.95% / **1.95% (Low)** | 1.62% / **1.62% (Low)** |
| **GitHub Developer Login** `[Enterprise Identity / SSO]` | 24.56% / **24.56% (Low)** | 25.89% / **25.89% (Low)** | 11.06% / **11.06% (Low)** |
| **GitLab DevSecOps Signin** `[Enterprise Identity / SSO]` | 37.78% / **20.78% (Low)** | 34.65% / **20.00% (Low)** | 51.21% / **28.16% (Low)** |
| **Okta Identity Cloud SSO** `[Enterprise Identity / SSO]` | 19.39% / **20.00% (Low)** | 19.64% / **20.00% (Low)** | 30.39% / **20.00% (Low)** |
| **Ping Identity Enterprise SSO** `[Enterprise Identity / SSO]` | 90.94% / **48.00% (Med)** | 89.62% / **48.00% (Med)** | 89.18% / **48.00% (Med)** |
| **Cisco Duo Security MFA** `[Enterprise Identity / SSO]` | 0.11% / **0.11% (Low)** | 0.07% / **0.07% (Low)** | 0.07% / **0.07% (Low)** |
| **Slack Enterprise Sign-In** `[Enterprise Identity / SSO]` | 66.68% / **36.67% (Med)** | 67.29% / **37.01% (Med)** | 75.29% / **41.41% (Med)** |
| **Oracle Single Sign-On** `[Enterprise Identity / SSO]` | 73.42% / **40.38% (Med)** | 76.77% / **42.22% (Med)** | 71.36% / **39.25% (Med)** |
| **Dropbox Cloud Storage Login** `[Enterprise Identity / SSO]` | 79.45% / **43.70% (Med)** | 81.19% / **44.65% (Med)** | 57.93% / **31.86% (Med)** |
| **Wikipedia Article** `[Standard Non-Auth Control]` | 0.43% / **0.43% (Low)** | 0.42% / **0.42% (Low)** | 0.35% / **0.35% (Low)** |
| **Raw IP PayPal Phishing** `[Phishing Attack]` | 92.88% / **92.88% (High)** | 90.87% / **90.87% (High)** | 93.99% / **93.99% (High)** |
| **Suspicious TLD Brand Phish** `[Phishing Attack]` | 99.77% / **99.77% (High)** | 99.68% / **99.68% (High)** | 99.47% / **99.47% (High)** |
| **Brand Spoof Apple ID** `[Phishing Attack]` | 99.88% / **99.88% (High)** | 99.83% / **99.83% (High)** | 99.85% / **99.85% (High)** |
| **DGA Brand Spoofing MS** `[Phishing Attack]` | 99.56% / **99.56% (High)** | 99.55% / **99.55% (High)** | 99.57% / **99.57% (High)** |
| **Tax Refund Credential Lure** `[Phishing Attack]` | 98.75% / **98.75% (High)** | 98.63% / **98.63% (High)** | 98.53% / **98.53% (High)** |
| **Subdomain Banking Phish** `[Phishing Attack]` | 98.72% / **98.72% (High)** | 99.15% / **99.15% (High)** | 98.30% / **98.30% (High)** |
| **Raw IP Netflix Lure** `[Phishing Attack]` | 84.87% / **84.87% (High)** | 81.60% / **81.60% (High)** | 87.21% / **87.21% (High)** |
| **Social Media Lure** `[Phishing Attack]` | 99.56% / **99.56% (High)** | 99.39% / **99.39% (High)** | 99.30% / **99.30% (High)** |
| **Crypto Seed Harvesting** `[Phishing Attack]` | 99.31% / **99.31% (High)** | 99.05% / **99.05% (High)** | 98.83% / **98.83% (High)** |
| **Banking Phishing Lure** `[Phishing Attack]` | 98.66% / **98.66% (High)** | 98.35% / **98.35% (High)** | 96.97% / **96.97% (High)** |

### 10.4 Single-Request Inference Latency (500 Runs Each)

| Model Artifact | Mean Latency | Median (P50) | P95 Latency | P99 Latency |
| :--- | :--- | :--- | :--- | :--- |
| **Current Production (Control Group)** | 8.899 ms | 8.742 ms | 9.727 ms | 10.707 ms |
| **Experimental Model 1 (`+is_institutional_domain`)** | 9.255 ms | 8.992 ms | 10.916 ms | 14.763 ms |
| **Experimental Model 2 (Targeted Data Augmentation)** | 8.640 ms | 9.141 ms | 11.072 ms | 12.374 ms |

### 10.5 Determinism Verification (5 Consecutive Runs Each)

- **Target: College Portal (`https://ps.bitsathy.ac.in`):**
  - Current Production: `[35.99%, 35.99%, 35.99%, 35.99%, 35.99%]` (Deterministic: **True**)
  - Experimental Model 1: `[20.00%, 20.00%, 20.00%, 20.00%, 20.00%]` (Deterministic: **True**)
  - Experimental Model 2: `[34.66%, 34.66%, 34.66%, 34.66%, 34.66%]` (Deterministic: **True**)
- **Target: Google Accounts Login (`https://accounts.google.com`):**
  - Current Production: `[86.50%, 86.50%, 86.50%, 86.50%, 86.50%]` (Deterministic: **True**)
  - Experimental Model 1: `[88.65%, 88.65%, 88.65%, 88.65%, 88.65%]` (Deterministic: **True**)
  - Experimental Model 2: `[76.87%, 76.87%, 76.87%, 76.87%, 76.87%]` (Deterministic: **True**)
- **Target: Salesforce Customer Portal (`https://login.salesforce.com`):**
  - Current Production: `[82.22%, 82.22%, 82.22%, 82.22%, 82.22%]` (Deterministic: **True**)
  - Experimental Model 1: `[80.27%, 80.27%, 80.27%, 80.27%, 80.27%]` (Deterministic: **True**)
  - Experimental Model 2: `[62.99%, 62.99%, 62.99%, 62.99%, 62.99%]` (Deterministic: **True**)
- **Target: TinyURL Web App (`https://tinyurl.com/app`):**
  - Current Production: `[32.08%, 32.08%, 32.08%, 32.08%, 32.08%]` (Deterministic: **True**)
  - Experimental Model 1: `[31.65%, 31.65%, 31.65%, 31.65%, 31.65%]` (Deterministic: **True**)
  - Experimental Model 2: `[27.61%, 27.61%, 27.61%, 27.61%, 27.61%]` (Deterministic: **True**)

---

## 11. Evolution Research Phase: Deep Diagnostic & Free-PaaS Subdomain Signal (Candidate Exp 3)

### 11.1 Evaluated Model Artifacts & Cryptographic Provenance
- **Current Production (Control Group):**
  - Path: `backend/ml/models/phishing_model.joblib`
  - SHA256: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`
  - Features: 43 features | Training Samples: 7,111 (`scale_pos_weight = 5.0`)
- **Experimental Model (Candidate Exp 3 — `+is_free_hosting_subdomain`):**
  - Path: `backend/ml/models/candidates_auth/candidate_exp3_paas_signal.joblib`
  - SHA256: `41761e991d9fd194d6ff2716566fa68694cba100ce337e8fce575c7ee0216e3f`
  - Features: 44 features | Training Samples: 7,111 (`scale_pos_weight = 5.0`)

### 11.2 Clean Held-Out Test Set Performance (1,799 Samples, 0.00% Domain Leakage)

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                        HELD-OUT TEST SET EVALUATION (1,799 Samples, 0.00% Leakage)                     │
├──────────────────────────────┬───────────────────┬───────────────────┬───────────────────┬─────────────┤
│ Metric                       │ Current Production│ Candidate Exp 3   │ Delta / Shift     │ Target /    │
│                              │ (Control)         │ (+paas_subdomain) │                   │ Floor       │
├──────────────────────────────┼───────────────────┼───────────────────┼───────────────────┼─────────────┤
│ Model SHA-256 (First 12)     │ 7a80ec64d1d3...   │ 41761e991d9f...   │ Verified Distinct │ Traceable   │
│ Accuracy                     │ 94.55%            │ 94.61%            │ +0.06%            │ > 94.0%     │
│ Precision                    │ 83.30%            │ 83.33%            │ +0.03%            │ > 82.0%     │
│ Phishing Recall (Sensitivity)│ 94.21% (374/397)  │ 94.46% (375/397)  │ +0.25% (+1 Caught)│ >= 94.0%    │
│ False Negatives (Missed)     │ 23 missed (5.79%) │ 22 missed (5.54%) │ -1 Missed Attack  │ <= 25 missed│
│ False Positives (False Alarm)│ 75 (5.35% FPR)    │ 75 (5.35% FPR)    │ 0 Net Increase    │ Lower = Good│
│ F1-Score                     │ 88.42%            │ 88.55%            │ +0.13%            │ > 88.0%     │
│ ROC-AUC                      │ 0.9819            │ 0.9843            │ +0.0024           │ > 0.980     │
│ Brier Score Loss             │ 0.0390            │ 0.0372            │ -0.0018 (Improved)│ < 0.040     │
│ Top-2 Feature Concentration  │ 43.06%            │ 42.11%            │ -0.95%            │ < 45.0%     │
├──────────────────────────────┼───────────────────┼───────────────────┼───────────────────┼─────────────┤
│ RECALL FLOOR STATUS (>=94.0%)│ PASS (94.21%)     │ PASS (94.46%)     │ PASS (>=94.0%)    │ MANDATORY   │
└──────────────────────────────┴───────────────────┴───────────────────┴───────────────────┴─────────────┘
```

### 11.3 Dedicated False Negative Recovery Benchmark
Evaluates detection capability on high-link cloned phishing attacks that previously slipped through production:

| Target Attack & Topology | Production Control (`7a80...`) Score / Verdict | Candidate Exp 3 (`4176...`) Score / Verdict | Forensic Analysis |
| :--- | :--- | :--- | :--- |
| **Cloned Netlify Phish** `(532 cloned links)` | 90.72% / **Caught** | 97.38% / **Caught** | Threat score escalated (+6.66%). |
| **Cloned Netlify HTTP Phish** `(532 links)` | 66.57% / **Caught** | 95.21% / **Caught** | Threat score escalated to decisive high risk. |
| **Cloudflare Pages Phish** `(100 links)` | 25.48% / **MISSED** | 68.41% / **Caught** | **RECOVERED:** Moved from False Negative to Caught. |
| **Cloudflare Pages Crypto Phish** `(92 links)` | 33.13% / **MISSED** | 75.02% / **Caught** | **RECOVERED:** Moved from False Negative to Caught. |
| **Shortened Redirection Phish** `(175 links)` | 35.64% / **MISSED** | 20.54% / **MISSED** | Requires multi-hop redirect following to resolve target. |

### 11.4 Single-Request Latency & Determinism
- **Inference Latency (500 Runs):** Mean = **10.147 ms** | P50 = **10.078 ms** | P95 = **12.116 ms** | P99 = **13.213 ms**
- **Determinism (5 Consecutive Runs):** 100.0% output determinism across all benchmark targets.


