# PhishGuard AI — ML Accuracy Diagnostic Report
**Production Model Version:** `2.1.0`  
**Model Architecture:** Balanced Regularized XGBoost (`XGBClassifier`)  
**Active Production Model SHA-256:** `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`  
**Diagnostic Execution Date:** `2026-09-16`  
**Evaluation Scope:** Read-only inspection of complete ML pipeline, datasets, features, and generalization slices.

---

## Executive Summary

| Diagnostic Dimension | Production Model (v2.1.0) Status | Target Production Constraint | Status / Health |
| :--- | :--- | :--- | :--- |
| **Overall Phishing Recall** | **98.56%** (Domain-Disjoint Test) | $\ge 94.00\%$ | ✅ **PASS** |
| **Overall Precision** | **89.15%** (Domain-Disjoint Test) | $\ge 85.00\%$ | ✅ **PASS** |
| **Overall Accuracy** | **96.86%** (Domain-Disjoint Test) | $\ge 95.00\%$ | ✅ **PASS** |
| **Domain Leakage in Evaluation** | **0.00%** (GroupKFold by domain) | $0.00\%$ | ✅ **CLEAN** |
| **Sparse Legitimate Page FPR** | **23.78%** ($44 / 185$ FPs on $\le 20$ links) | $< 5.00\%$ | ❌ **CRITICAL VULNERABILITY** |
| **Shortened URL Phishing Recall** | **83.33%** ($5 / 6$ caught) | $\ge 94.00\%$ | ⚠️ **AT-RISK SUBCLASS** |
| **Top 2 Feature Concentration** | **43.06%** (`num_links` + `num_internal_links`) | $< 30.00\%$ | ⚠️ **SHORTCUT LEARNING** |
| **Feature Collinearity** | **$r = 0.9717$** (`num_links` vs `num_internal_links`) | $r < 0.80$ | ⚠️ **HIGH REDUNDANCY** |

---

## 1. Dataset Composition Analysis

### 1.1 Sample Volume & Class Balance
* **Total Clean Samples:** $8,910$ samples in `backend/data/processed/training_dataset_expanded.csv` ($8,958$ in original `training_dataset.csv`).
* **Legitimate Class Count:** $7,005$ samples ($78.62\%$).
* **Phishing Class Count:** $1,905$ samples ($21.38\%$).
* **Imbalance Ratio:** $3.6772 : 1$ (Legitimate to Phishing).
* **Unique URLs:** $8,910$ ($0$ duplicates).
* **Unique Registered Domains:** $3,049$ unique domains.
* **Missing Values:** $0$ missing values across all $43$ tabular feature columns.
* **Operational Parse Errors:** $0$ URL parse errors, $68$ HTML parse errors ($0.76\%$, handled gracefully via fallback vectors).

### 1.2 Data Ingestion & Source Breakdown
Data sources traced via `dataset_manifest.csv` ($31,171$ raw records):
* **PhishTank:** $1,709$ phishing samples ($89.7\%$ of phishing corpus).
* **OpenPhish:** $196$ phishing samples ($10.3\%$ of phishing corpus).
* **Tranco Top-1M Seed Homepages:** $2,512$ legitimate samples ($35.9\%$ of legitimate corpus).
* **Tranco Internal Deep-Link Crawl:** $3,841$ legitimate samples ($54.8\%$ of legitimate corpus).
* **Curated Diverse Subdomain & Form Seed Collection:** $652$ legitimate samples ($9.3\%$).

### 1.3 Structural & Feature Distributions Across Classes
| Metric / Feature | Legitimate Corpus ($N=7,005$) | Phishing Corpus ($N=1,905$) | Structural Distortion / Delta |
| :--- | :--- | :--- | :--- |
| **Median Total Link Count (`num_links`)** | **$104.0$** ($\mu=149.48$, IQR: $43-191$) | **$2.0$** ($\mu=19.27$, IQR: $0-9$) | **$52.0\times$ link volume skew** |
| **Median Internal Links (`num_internal_links`)** | **$93.0$** ($\mu=134.12$) | **$1.0$** ($\mu=14.38$) | **$93.0\times$ internal link skew** |
| **Login Form Presence (`has_login_form`)** | $1,154$ ($16.47\%$) | $352$ ($18.48\%$) | Nearly identical form rates |
| **Password Input Fields (`num_password_fields > 0`)** | $236$ ($3.37\%$) | $203$ ($10.66\%$) | $3.16\times$ higher in phishing |
| **SPA / Minimalist Webpage Shells** | $859$ ($12.26\%$) | $1,084$ ($56.90\%$) | $4.64\times$ higher in phishing |
| **HTTPS Encryption Adoption (`uses_https`)** | $6,952$ ($99.24\%$) | $1,794$ ($94.17\%$) | Phishing is overwhelmingly HTTPS |

### 1.4 Top Registered Domains & Infrastructure Distribution
* **Top Phishing Platforms:** Phishing is concentrated in cloud hosting, free subdomains, and PaaS website builders: `google.com` ($176$ docs/forms lures), `vercel.app` ($168$), `pages.dev` ($77$), `webflow.io` ($56$), `netlify.app` ($54$), `gitbook.io` ($43$), `iceiy.com` ($43$), `github.io` ($37$), `blogspot.com` ($34$), `framer.app` ($32$).
* **Top Legitimate Domains:** Institutional domains: `gov.in` ($77$), `ac.in` ($53$), `ac.uk` ($40$), `co.uk` ($38$), `com.br` ($35$), `edu.au` ($32$), `co.jp` ($26$), `gov.uk` ($16$).
* **TLD Distribution:**
  * Legitimate: `.com` ($51.36\%$), `.org` ($8.07\%$), `.edu` ($3.71\%$), `.net` ($3.70\%$), `.gov` ($3.07\%$).
  * Phishing: `.com` ($35.80\%$), `.app` ($17.74\%$), `.io` ($8.14\%$), `.dev` ($5.30\%$), `.me` ($2.41\%$), `.run` ($1.26\%$).

---

## 2. Data Leakage Analysis

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              DATA SPLITTING LEAKAGE COMPARISON                         │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  Standard Stratified Random Split (80/20):                                             │
│  ├── Total Test Domains: 1,241                                                         │
│  ├── Domain Overlap with Train: 1,014 domains (81.71% LEAKAGE) ──► Falsely optimistic  │
│                                                                                        │
│  Domain-Disjoint GroupKFold Split (80/20 by Apex Domain):                              │
│  ├── Total Test Domains: 610                                                           │
│  ├── Domain Overlap with Train: 0 domains (0.00% LEAKAGE)     ──► Honest out-of-domain │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

1. **Domain Overlap in Random Splits:** When using standard `train_test_split(stratify=y)` as in early baselines (`backend/ml/training/train_baseline_models.py:66-72`), **$81.71\%$ of test domains were already present in the training set**. This caused tree classifiers to memorize domain-specific artifacts rather than learning generalized phishing signals.
2. **Domain-Disjoint Splitting Enforcement:** Under strict `GroupKFold(groups=df['reg_domain'])` (`backend/ml/training/train_and_calibrate_v2_2.py:88-99`), domain overlap is exactly **$0.00\%$**.
3. **Exact Feature Vector Duplication:** $0$ duplicate feature vectors across distinct URLs.

---

## 3. Production Model Performance & Evaluation

The active production model (`phishing_model.joblib`, version `2.1.0`, `scale_pos_weight=5.0`) was evaluated on the held-out Domain-Disjoint test set ($N=1,782$ samples, $0\%$ domain overlap):

| Metric | Score | Detailed Interpretation |
| :--- | :--- | :--- |
| **Accuracy** | **$96.86\%$** | High overall classification accuracy across unseen domains |
| **Phishing Recall** | **$98.56\%$** | Catches $411$ out of $417$ phishing attacks ($6$ false negatives) |
| **Precision** | **$89.15\%$** | $411$ true attacks out of $461$ positive alerts ($50$ false positives) |
| **F1-Score** | **$93.62\%$** | Strong harmonic mean between precision and recall |
| **Specificity** | **$96.34\%$** | Correctly identifies $1,315$ out of $1,365$ legitimate websites |
| **False Positive Rate (FPR)** | **$3.66\%$** | $50 / 1,365$ legitimate websites incorrectly flagged |
| **False Negative Rate (FNR)** | **$1.44\%$** | $6 / 417$ phishing attacks missed |
| **ROC-AUC** | **$0.9976$** | High discriminative capacity across decision boundaries |
| **PR-AUC (Avg Precision)** | **$0.9927$** | Sustained precision across high-recall operating points |
| **Brier Score** | **$0.0222$** | Low quadratic penalty on binary outcomes |

### Confusion Matrix Breakdown (Domain-Disjoint Test Set, $N=1,782$)
$$\begin{pmatrix} \text{True Negatives (TN): } 1315 & \text{False Positives (FP): } 50 \\ \text{False Negatives (FN): } 6 & \text{True Positives (TP): } 411 \end{pmatrix}$$

### Probability & Risk-Score Distribution
* **Low Risk ($\text{prob} < 0.30$):** $1,281$ samples ($71.9\%$)
* **Medium Risk ($0.30 \le \text{prob} < 0.70$):** $76$ samples ($4.3\%$)
* **High Risk ($\text{prob} \ge 0.70$):** $425$ samples ($23.8\%$)
* **Score Percentiles:** $p_{10} = 0.0022$, $p_{25} = 0.0037$, $p_{50} = 0.0171$, $p_{75} = 0.5503$, $p_{90} = 0.9891$, $p_{99} = 0.9983$.
* **Calibration Note:** Due to `scale_pos_weight = 5.0`, output probabilities represent monotonic ordinal threat scores rather than true empirical probabilities (`backend/ml/models/model_metadata.json:56`).

---

## 4. In-Depth Error Analysis

### 4.1 False Positive Breakdown ($50$ Misclassified Legitimate Sites)
The primary driver of false positives is **sparse link count** on legitimate subpages, institutional forms, contact portals, and minimalist Single Page Applications.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               FALSE POSITIVE PROFILE VS TRUE NEGATIVES                 │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  False Positives (N=50):     Median Links = 0.0  │ Mean Links = 8.08   │ Sparse = 88.0%│
│  True Negatives (N=1,315):   Median Links = 108.0│ Mean Links = 147.37 │ Sparse = 10.7%│
└────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Top Representative False Positives:
1. `https://register.state.gov/contactus/contactusform` ($\hat{p} = 0.9155$) — U.S. State Dept contact form. `num_links=0`, `domain_len=18`.
2. `https://facilities.aicte-india.org/report/` ($\hat{p} = 0.8981$) — AICTE Indian Education Portal report generator. `num_links=0`, `domain_len=26`.
3. `https://facilities.aicte-india.org/pgdm/` ($\hat{p} = 0.8940$) — AICTE PGDM portal. `num_links=2`, `domain_len=26`.
4. `https://mediakit.infobae.com/contactocomercial/colombia` ($\hat{p} = 0.8727$) — Infobae media kit. `num_links=0`, `domain_len=20`.
5. `https://community.joomla.org/user-groups.html` ($\hat{p} = 0.8620$) — Joomla user community page. `num_links=0`, `domain_len=20`.
6. `https://customerservice.aliexpress.com/category?...` ($\hat{p} = 0.8564$) — AliExpress customer support category page. `num_links=0`, `domain_len=30`, `has_suspicious_keywords=1`.
7. `https://console.fyber.com/login` ($\hat{p} = 0.8254$) — Fyber developer console. `num_links=0`, `domain_len=17`, `has_suspicious_keywords=1`.
8. `https://sso.pushwoosh.com/login` ($\hat{p} = 0.8088$) — Pushwoosh enterprise SSO portal. `num_links=0`, `domain_len=17`, `has_suspicious_keywords=1`.
9. `https://academy.amnesty.org/learn` ($\hat{p} = 0.8074$) — Amnesty International learning academy. `num_links=0`, `domain_len=19`.

### 4.2 False Negative Breakdown ($6$ Missed Phishing Sites)
Phishing attacks that succeeded in bypassing detection exhibit one of two specific evasion patterns:
1. **High Link Emulation / Multi-Link Phishing Hubs:**
   * `https://linktr.ee/Newmaiiiling` ($\hat{p} = 0.4232$) — Phishing lure built on Linktree profile containing $56$ links ($55$ internal navigation links), bypassing the low-link tree threshold.
   * `https://sites.google.com/view/tapecaria-dias/` ($\hat{p} = 0.4411$) — Google Sites phishing page with $19$ internal links and short clean domain name.
   * `https://ashutoshhospital.com/Korea.html` ($\hat{p} = 0.3965$) — Compromised hospital website with $61$ links and $37$ script tags hosting a phishing form.
2. **Minimalist Domain Camouflage with HTTPS:**
   * `https://acessopj.com` ($\hat{p} = 0.0963$) — Brand new domain with standard length ($12$ chars), HTTPS enabled, and no obvious keywords in URL.
   * `https://www.abapj.com` ($\hat{p} = 0.3190$) — Clean lexical structure with HTTPS.
   * `https://loveaeen.com` ($\hat{p} = 0.3194$) — Credential lure with $17$ internal links.

---

## 5. Feature Importance, Multicollinearity & Shortcut Learning

### 5.1 Top 15 Feature Importances (XGBoost Gain vs Permutation Importance)
| Feature Name | Data Type | Tree Importance (Gain) | Permutation Importance (Recall Drop) | Multicollinearity / Notes |
| :--- | :--- | :--- | :--- | :--- |
| **`num_links`** | `int64` | **$0.2647$** ($26.47\%$) | $0.0475 \pm 0.0065$ | Correlated with `num_internal_links` ($r=0.9717$) |
| **`num_internal_links`** | `int64` | **$0.1659$** ($16.59\%$) | **$0.2086 \pm 0.0175$** | Primary driver of permutation drop |
| **`num_external_links`** | `int64` | **$0.0654$** ($6.54\%$) | $0.0067 \pm 0.0018$ | External link count |
| **`domain_length`** | `int64` | **$0.0480$** ($4.80\%$) | $0.0379 \pm 0.0032$ | Penalizes long legitimate subdomains |
| **`uses_https`** | `int64` | **$0.0358$** ($3.58\%$) | $0.0120 \pm 0.0000$ | Binary HTTPS indicator |
| **`external_link_ratio`** | `float64` | **$0.0303$** ($3.03\%$) | $0.0019 \pm 0.0005$ | Ratio of external to total links |
| **`path_length`** | `int64` | **$0.0255$** ($2.55\%$) | $0.0307 \pm 0.0059$ | URL path character count |
| **`num_digits`** | `int64` | **$0.0235$** ($2.35\%$) | $0.0043 \pm 0.0044$ | Digit count in URL string |
| **`num_slashes`** | `int64` | **$0.0229$** ($2.29\%$) | $0.0019 \pm 0.0010$ | Correlated with `path_depth` ($r=0.9341$) |
| **`path_depth`** | `int64` | **$0.0196$** ($1.96\%$) | $0.0014 \pm 0.0010$ | Path slash segment count |
| **`num_subdomains`** | `int64` | **$0.0188$** ($1.88\%$) | $0.0010 \pm 0.0005$ | Correlated with `num_dots` ($r=0.7562$) |
| **`num_dots`** | `int64` | **$0.0177$** ($1.77\%$) | $0.0019 \pm 0.0010$ | Dot count in URL |
| **`num_iframes`** | `int64` | **$0.0167$** ($1.67\%$) | $0.0010 \pm 0.0005$ | Total iframe count |
| **`url_length`** | `int64` | **$0.0163$** ($1.63\%$) | $0.0110 \pm 0.0024$ | Total character count of URL |
| **`has_login_form`** | `int64` | **$0.0151$** ($1.51\%$) | $0.0019 \pm 0.0010$ | HTML login form detection |

### 5.2 Feature Concentration & Shortcut Learning Risks
1. **Top 2 Feature Concentration ($43.06\%$):** `num_links` and `num_internal_links` comprise nearly half of all split importance in the tree ensemble.
2. **Severe Collinearity ($r = 0.9717$):** `num_links` and `num_internal_links` are essentially duplicate signals. Because Tranco root homepages have extensive internal menus and PhishTank landing pages have none, the model learned a strong **shortcut**: $\text{few links} \implies \text{phishing}$.
3. **Lexical Domain Length Penalty:** `domain_length` is the #4 overall feature. Multi-part institutional hostnames (e.g. `*.gov.in`, `*.state.gov`) are unfairly penalized.

---

## 6. Generalization & Subclass Slice Tests

| Test Slice / Subclass | Sample Size ($N$) | Metric Evaluated | Performance Score | Vulnerability Assessment |
| :--- | :--- | :--- | :--- | :--- |
| **Legitimate Login / SSO Portals** | $195$ samples | False Positive Rate | **$1.54\%$** ($3$ FPs) | **LOW RISK** — Legitimate portals with sufficient links pass cleanly. |
| **Sparse Legitimate Pages ($\le 20$ links)** | $185$ samples | False Positive Rate | **$23.78\%$** ($44$ FPs) | ❌ **CRITICAL** — $88\%$ of all false positives occur here. |
| **Shortened URL Phishing** | $6$ samples | Phishing Recall | **$83.33\%$** ($5 / 6$ caught) | ⚠️ **AT-RISK** — Fails $\ge 94\%$ constraint on link-hub attacks. |
| **HTTPS Phishing Attacks** | $393$ samples | Phishing Recall | **$98.47\%$** ($387 / 393$ caught) | **PASS** — Strong defense against HTTPS-encrypted phishing. |
| **Sparse Phishing Attacks ($\le 20$ links)**| $363$ samples | Phishing Recall | **$98.90\%$** ($359 / 363$ caught) | **PASS** — Catches virtually all standard sparse lures. |

---

## 7. Model Architecture & Hyperparameter Specifications

* **Current Algorithm:** `xgboost.XGBClassifier` (`backend/ml/models/model_metadata.json:5`)
* **Model Version:** `2.1.0`
* **Artifact File:** `backend/ml/models/phishing_model.joblib`
* **Model SHA-256:** `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`
* **Active Hyperparameters:**
  ```json
  {
    "colsample_bytree": 0.7,
    "learning_rate": 0.05,
    "max_depth": 4,
    "n_estimators": 200,
    "reg_lambda": 1.0,
    "scale_pos_weight": 5.0,
    "subsample": 0.95
  }
  ```
* **Decision & Scoring Architecture:**
  * Binary threshold: $0.50$ (Model level).
  * Production Risk Level Mapping (`backend/app/services/risk_scoring.py:58-78`):
    * Low Risk: $\text{prob} < 0.30$
    * Medium Risk: $0.30 \le \text{prob} < 0.70$
    * High Risk: $\text{prob} \ge 0.70$
  * Degraded Mode & SPA Handling (`backend/app/services/risk_scoring.py:80-133`): When static HTML is unavailable or content rendering is incomplete, scores on clean URLs are dampened and bounded to $\le 0.48$ (capped at `Suspicious` / `Medium`), avoiding false `Phishing` alerts.

---

## 8. Ranked List of the Five Highest-Value Accuracy Problems

### 1. Link-Count Dominance & Shortcut Learning (False Positive Driver)
* **Root Cause:** `num_links` and `num_internal_links` control $43.06\%$ of tree gain with $r = 0.9717$ collinearity.
* **Impact:** Generates a **$23.78\%$ False Positive Rate** on sparse legitimate pages ($44$ of $50$ total false positives).
* **Code References:** `backend/ml/models/model_metadata.json:38-41`, `backend/ml/feature_extraction/html_features.py:110-150`.

### 2. Historical Evaluation Contamination in Naive Stratified Splits
* **Root Cause:** Standard random split produced $81.71\%$ domain leakage ($1,014$ overlapping domains), causing baseline models to artificially report $97.8\%$ accuracy while overfitting.
* **Impact:** Masks true out-of-domain errors. All future experiments must strictly utilize domain-disjoint GroupKFold.
* **Code References:** `backend/ml/training/train_baseline_models.py:66-72`, `backend/ml/training/train_and_calibrate_v2_2.py:88-99`.

### 3. Shortened URL & Social Link-Hub Phishing Blind Spot (False Negative Vector)
* **Root Cause:** Phishing hosted on landing hubs (`linktr.ee`, `sites.google.com`) contains numerous internal links, effectively neutralizing the model's primary link-based heuristic.
* **Impact:** Phishing recall drops to **$83.33\%$** on shortened/hub lures, breaching the $\ge 94\%$ recall constraint.
* **Code References:** `backend/ml/feature_extraction/url_features.py:116-140`, `scratch/diagnostic_summary.json:474-498`.

### 4. Positive Probability Calibration Distortion (`scale_pos_weight = 5.0`)
* **Root Cause:** Scaling positive gradient weights by $5.0\times$ skews raw logistic sigmoid outputs toward high risk without post-hoc probability calibration.
* **Impact:** Ambiguous samples artificially jump to $0.80-0.92$ probability rather than reflecting true posterior likelihood.
* **Code References:** `backend/ml/training/tune_and_finalize_model.py:163-172`, `backend/app/services/risk_scoring.py:58-78`.

### 5. Multi-Part Institutional Domain Length Penalization
* **Root Cause:** `domain_length` is the 4th most important feature ($4.80\%$ gain).
* **Impact:** Legitimate government and educational portals with descriptive subdomains (e.g. `facilities.aicte-india.org`, `customerservice.aliexpress.com`) accumulate high suspicion points solely due to character length.
* **Code References:** `backend/ml/feature_extraction/url_features.py:97`, `scratch/diagnostic_summary.json:251-360`.

---

## 9. Recommended Next Experiment

### Recommended Intervention Category:
**Feature Engineering + Dataset Improvement (Dual-Phased Out-of-Sample Validation)**

### Detailed Action Plan:
1. **Feature Engineering Interventions:**
   * **De-correlate Link Features:** Remove or regularize `num_internal_links` (which has $r=0.9717$ redundancy with `num_links`).
   * **Introduce Ratio-Based Normalization:** Add `link_density_per_kb_html` and `internal_to_total_link_ratio` rather than relying exclusively on absolute link counts.
   * **Domain-to-Path Ratio:** Replace raw `domain_length` with `subdomain_to_apex_length_ratio` to prevent penalizing legitimate institutional apex domains.
2. **Dataset Diversification:**
   * Ingest `diverse_legitimate_records.csv` ($671$ curated sparse subpages, university forms, and government portals) into the training fold of a 5-fold Domain-Disjoint GroupKFold.
3. **Model & Hyperparameter Tuning:**
   * Tune `colsample_bytree \in [0.55, 0.65]` to force tree diversity away from link features.
   * Test `scale_pos_weight \in [3.5, 4.2]` combined with Isotonic / Sigmoid probability calibration.
4. **Acceptance Criteria for Promotion:**
   * Overall Phishing Recall $\ge 94.00\%$ on domain-disjoint test set.
   * Sparse Legitimate Page FPR reduced from **$23.78\% \implies < 5.00\%$**.
   * Shortened URL Phishing Recall improved from **$83.33\% \implies \ge 94.00\%$**.
   * Feature concentration of top 2 features reduced from **$43.06\% \implies < 30.00\%$**.
   * Zero replacement of production artifacts until candidate is fully verified.

---

## 10. Reproducibility Command

To re-run the entire diagnostic pipeline and generate updated metric artifacts:

```powershell
backend\venv\Scripts\python.exe scratch\run_full_ml_diagnostic.py
```

*Output Artifacts:*
* Machine-Readable JSON: `scratch/diagnostic_summary.json`
* Markdown Diagnostic Report: `docs/ML_ACCURACY_DIAGNOSTIC_REPORT.md`
