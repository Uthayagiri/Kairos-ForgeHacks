# PhishGuard AI — Methodology & Machine Learning Engineering

## 1. Data Collection & Dataset Curation

### 1.1 Data Sources
To construct a representative, high-fidelity dataset, data was acquired from three authoritative cybersecurity feeds:

1. **Tranco Top Sites Ranking (List ID `74V6X`):** A research-oriented top-sites list combining Alexa, Cisco Umbrella, Majestic, and Chrome UX rankings to avoid single-source domain bias. Used as the primary source for high-reputation legitimate websites.
2. **PhishTank Verified Active Feed (`online-valid.csv`):** Verified community-submitted active phishing campaigns containing fully resolved target URLs.
3. **OpenPhish Community Feed (`feed.txt`):** High-confidence zero-day phishing telemetry updated continuously.

### 1.2 Dataset Composition & Class Distribution
The raw candidate pool was deduplicated, validated, and normalized before concurrent HTML fetching. The dataset was augmented with 671 new legitimate samples across educational (`.edu`, `.ac.in`), governmental (`.gov`, `.gov.in`), minimalist utility, and non-profit domains to resolve link-count distribution skew. Following an audit that purged 719 duplicate/near-identical feature records, the final consolidated dataset (`training_dataset_expanded.csv`) contains **8,910 verified samples** across **3,151 unique registered domains**:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       FINAL DATASET COMPOSITION (8,910 Rows)                │
├─────────────────────────────────────────┬──────────────┬────────────────────┤
│ Category / Class Source                 │ Sample Count │ Percentage         │
├─────────────────────────────────────────┼──────────────┼────────────────────┤
│ Legitimate: Tranco Roots & Deep Links   │ 5,843        │ 65.58%             │
│ Legitimate: Expanded Edu/Gov/Tools      │   671        │  7.53%             │
│ Phishing: PhishTank & OpenPhish Attacks │ 2,396        │ 26.89%             │
├─────────────────────────────────────────┼──────────────┼────────────────────┤
│ TOTAL LEGITIMATE SAMPLES                │ 6,514        │ 73.11%             │
│ TOTAL PHISHING SAMPLES                  │ 2,396        │ 26.89%             │
├─────────────────────────────────────────┼──────────────┼────────────────────┤
│ Unique Registered Domains               │ 3,151        │                    │
│ Class Imbalance Ratio (Neg / Pos)       │ 2.7187 : 1   │                    │
│ Total Features Extracted                │ 43 Features  │                    │
└─────────────────────────────────────────┴──────────────┴────────────────────┘
```

### 1.3 Domain-Grouped Partitioning Strategy (Eliminating Data Leakage)
In initial stages, random stratified splitting resulted in **84.03% domain overlap leakage** between training and test sets (1,073 of 1,277 test domains were present in training), allowing models to memorize domain-specific structures.

To establish genuine generalization to unseen web architectures, the dataset is partitioned using **GroupShuffleSplit on registered domain** (`test_size=0.20, random_state=42`):
- **Training Set:** `7,111` samples across `2,520` domains (5,603 Legitimate, 1,508 Phishing).
- **Held-Out Test Set:** `1,799` samples across `631` domains (1,402 Legitimate, 397 Phishing).
- **Domain Overlap Leakage:** **0.00%** (zero domain overlap between train and test).

---

## 2. Four Major Bias Discoveries & Engineering Solutions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      THE 4 CORE BIAS RESOLUTIONS SUMMARY                    │
├───────────────────┬──────────────────────────────────┬──────────────────────┤
│ Discovery Stage   │ Nature of Problem                │ Engineering Solution │
├───────────────────┼──────────────────────────────────┼──────────────────────┤
│ Stage 6 Finding   │ Path Length Shortcut Bias        │ Deep-Link Crawling   │
│                   │ (Tranco roots had path_length=0) │ & Data Augmentation  │
├───────────────────┼──────────────────────────────────┼──────────────────────┤
│ Stage 8 Finding   │ Degraded Mode False Alarms       │ Dual-Branch Damped   │
│                   │ (WAF blocks imputed as lures)    │ Probability Scoring  │
├───────────────────┼──────────────────────────────────┼──────────────────────┤
│ Stage 12 Finding  │ SPA Empty Shell Misclassification│ Structural SPA Shell │
│                   │ (React/Vue empty root DOMs)      │ Detection Heuristics │
├───────────────────┼──────────────────────────────────┼──────────────────────┤
│ Stage 15 Finding  │ Link-Count Over-Reliance &       │ Data Diversification,│
│                   │ Domain Memorization Leakage      │ Feature Subsampling  │
│                   │ (59.3% split weight on links)    │ & Regularized Tuning │
└───────────────────┴──────────────────────────────────┴──────────────────────┘
```

### 2.1 Bias 1: Path Length Shortcut Bias & Deep-Link Augmentation (Stage 6)
- **The Finding:** Tranco Top 1M roots had `path_length = 0`, whereas PhishTank entries had deep subpaths. Models learned an ungeneralizable shortcut: *any URL with a non-trivial path was classified as phishing*.
- **The Engineering Fix:** We crawled and augmented the dataset with **3,963 legitimate internal subpages**, forcing the classifier to learn genuine structural indicators.

### 2.2 Bias 2: Degraded Mode HTML-Unavailable Bias & Dual-Branch Dampening (Stage 8)
- **The Finding:** Server-side fetch failures (WAF 403 blocks, timeouts) default HTML features to 0, which mimics stripped phishing lures.
- **The Engineering Fix:** Implemented **Dual-Branch Damped Probability Scoring** in `risk_scoring.py`, capping risk scores to Low/Medium when HTML is unavailable and the URL is lexically clean.

### 2.3 Bias 3: Single-Page Application (SPA) Empty-Shell Detection (Stage 12)
- **The Finding:** Modern SPAs deliver minimal initial HTML shells with 0 static forms/links, causing static classifiers to trigger false alarms.
- **The Engineering Fix:** Engineered dedicated SPA detection heuristics setting `content_rendering_incomplete = True` with calibrated risk bounds and distinct UI notices.

### 2.4 Bias 4: Link-Count Over-Reliance & Regularized Tuning (Stage 15)
- **The Finding:** 59.26% of model split weight was concentrated in `num_links` and `num_internal_links`, and 84.03% domain overlap in random splits masked low-link false alarms.
- **The Engineering Fix:** Shifted to zero-leakage domain-grouped splitting, augmented data with 671 low-link legitimate pages, and applied regularized gradient boosting (`colsample_bytree = 0.70`, `max_depth = 4`, `scale_pos_weight = 5.0`) to reduce top-2 feature weight to **43.06%** while maintaining **94.21% test recall** on unseen domains.

---

## 3. Feature Engineering Pipeline (43 Features)

The system extracts **43 numerical and binary features** structured into two distinct domains:

### 3.1 URL Features (22 Features)
Defined in `backend/ml/feature_extraction/url_features.py`:
- Lexical length metrics: `url_length`, `domain_length`, `path_length`, `path_depth`
- Delimiter and character counts: `num_dots`, `num_hyphens`, `num_underscores`, `num_slashes`, `num_digits`, `num_special_chars`
- Structural indicators: `num_subdomains`, `num_query_params`, `has_at_symbol`, `has_ip_address`, `uses_https`, `has_port`, `has_url_encoding`
- Reputation & heuristic flags: `has_suspicious_tld`, `has_suspicious_keywords`, `has_double_slash_redirect`, `is_shortened_url`, `url_parse_error`

### 3.2 HTML & DOM Features (21 Features)
Defined in `backend/ml/feature_extraction/html_features.py`:
- Form & authentication metrics: `num_forms`, `num_input_fields`, `num_password_fields`, `has_login_form`, `num_forms_with_external_action`, `has_form_action_empty_or_javascript`
- Hyperlink topology: `num_links`, `num_internal_links`, `num_external_links`, `external_link_ratio`, `num_links_with_mismatched_text`
- Scripting & frame indicators: `num_scripts`, `num_iframes`, `has_hidden_iframe`, `has_suspicious_js_patterns`, `num_meta_refresh_redirects`
- Structural & content ratios: `title_length`, `has_favicon`, `num_images`, `text_to_html_ratio`, `html_parse_error`

---

## 4. Production Model Selection & Hyperparameters

The deployed classifier is **Candidate A4** (`backend/ml/models/phishing_model.joblib`, Version `2.1.0`):

```json
{
  "model_name": "Balanced Regularized XGBoost Phishing Detector (Candidate A4)",
  "version": "2.1.0",
  "algorithm": "XGBClassifier",
  "hyperparameters": {
    "colsample_bytree": 0.7,
    "learning_rate": 0.05,
    "max_depth": 4,
    "n_estimators": 200,
    "reg_lambda": 1.0,
    "scale_pos_weight": 5.0,
    "subsample": 0.95
  },
  "metrics": {
    "accuracy": 0.9455,
    "precision": 0.8330,
    "recall": 0.9421,
    "f1_score": 0.8842,
    "roc_auc": 0.9819,
    "brier_score": 0.0390
  }
}
```

**Architectural Rationale:**
1. **High Cybersecurity Recall (94.21%):** `scale_pos_weight = 5.0` prioritizes catching malicious phishing attacks on unseen domains (capturing 374 of 397 attacks, with only 23 missed).
2. **Substantially Reduced Concentration (43.06%):** Restricting `colsample_bytree = 0.70` prevents single-feature dominance and elevates `num_external_links`, `domain_length`, and `uses_https`.
3. **Fast Native Inference (9.89 ms):** Avoids multi-model calibration ensemble overhead, ensuring rapid API turnaround.

---

## 5. Stale-Model Protection Mechanism & Runtime Integrity

### 5.1 The Stale-Model Failure Mode
In production ML microservices, a common silent failure occurs when the model artifact on disk (`phishing_model.joblib`) is upgraded or retrained, but the long-running FastAPI/uvicorn server process continues serving an obsolete in-memory model loaded at startup. This produces a silent divergence between code on disk and runtime behavior.

### 5.2 Engineering Solution: Thread-Safe Auto-Reload with Content Hashing
To eliminate this failure mode without restarting server processes or introducing heavyweight orchestration frameworks, `ModelLoader` in `backend/app/core/model_loader.py` implements:

1. **Monotonic File Modification Tracking:** `ModelLoader` checks the `mtime` of `phishing_model.joblib` with a 1.0-second rate-limiting throttle (`_check_interval_seconds = 1.0`) to avoid disk stat syscall overhead on high-throughput requests.
2. **SHA-256 Artifact Integrity Verification:** Computes the full 64-character SHA-256 hash of the on-disk model upon detection of file modification.
3. **Thread-Safe Atomic Swap:** Uses a recursive re-entrant lock (`threading.RLock`) to load new joblib/JSON artifacts into temporary variables and atomically re-bind internal references (`self._model`, `self._feature_columns`, `self._metadata`), guaranteeing zero race conditions and zero partially-loaded states under concurrent requests.
4. **Runtime Telemetry Endpoints:** Exposes `/model/info` returning full active runtime metadata (`sha256_hash`, `model_path`, `model_version`, `load_count`, `load_timestamp`, `file_mtime`) for instant external verification, while maintaining `/health` returning `{"status": "ok"}` for standard orchestrator health probes.

---

## 6. Controlled `scale_pos_weight` Experiment Methodology

### 6.1 Scientific Variable Isolation
To evaluate the isolated effect of positive class weighting (`scale_pos_weight`), models were trained with `scale_pos_weight` set to `3.5` (Candidate A), `4.0` (Candidate B), and `5.0` (Current Production baseline). All other training parameters, dataset partitions (8,910 rows, 0% domain leakage), and feature pipelines were kept identical.

### 6.2 Objective Decision Criteria
- **Recall Floor:** Phishing recall must remain $\ge 94.0\%$. (Any candidate failing this is rejected to preserve attack detection capability).
- **False Positive Reduction:** Legitimate-site false positives must be reduced without an unacceptable surge in false negatives.
- **Real-World Generalization:** Improvement must hold across the full benchmark suite, not just known problematic login pages.
- **Feature Concentration:** Top-2 feature split gain must remain $< 45.0\%$.
- **Inference Latency:** Sub-15ms inference latency must be maintained.

---

## 7. Research Methodology: Legitimate Auth / SSO / Institutional Portals Investigation

### 7.1 Diagnostic Audit Findings
A comprehensive feature space and training distribution audit revealed that:
1. **Low-Link Contrastive Asymmetry:** In the training dataset, **78.71% of phishing attacks** have $\le 10$ links, while only **1.30% of legitimate training examples** (73 samples) are login pages with $\le 10$ links and login forms.
2. **Tree Margin Penalties:** Because the tree splits assign high positive log-odds (+0.60 to +1.02) to pages with $\le 8$ links, legitimate dedicated authentication portals (Google, Salesforce, Harvard, Stanford) accumulate elevated threat scores due to their clean, focused UI topology.

### 7.2 Experimental Interventions Evaluated
1. **Experimental Model 1 (`candidate_exp1_inst_feature.joblib`, SHA256 `ee2bcb883400...`):**
   - Added an explicit `is_institutional_domain` structural signal (44 features).
   - *Outcome:* Dropped risk scores on educational portals (Bannari Amman College to 9.79%, Harvard Canvas to 5.04%, Stanford WebLogin to 40.82%), but had zero impact on commercial enterprise SSO portals (`accounts.google.com` 88.65%, `login.salesforce.com` 80.27%) and dropped test phishing recall to **93.70%** (failing the $\ge 94.0\%$ floor).
2. **Experimental Model 2 (`candidate_exp2_aug_data.joblib`, SHA256 `95a3418cc152...`):**
   - Targeted training data augmentation of 300 legitimate sparse/auth pages (7,411 training samples).
   - *Outcome:* Reduced false positive risk across commercial login portals (Salesforce to 62.99%, Atlassian to 48.52% / 26.69% final), but softened low-link splits, dropping test phishing recall to **91.94%** (failing the $\ge 94.0\%$ floor).

### 7.3 Final Governance Decision
Because both experimental models failed the mandatory 94.0% recall floor on the clean held-out domain test set, **Current Production (`phishing_model.joblib`, SHA256 `7a80ec64d1d3...`) is retained unchanged in production**. Any promotion of future models requires separate explicit human authorization.

---

## 8. Evolution Methodology: Deep Diagnostic & Free-PaaS Subdomain Signal (Candidate Exp 3)

### 8.1 Diagnostic Findings & False Negative Root Cause
Deep inspection of the 23 false negatives missed by current production revealed that:
1. **High-Link Phishing Clones:** 87.0% (20/23) of missed attacks had >20 links scraped from real target brands.
2. **Free Cloud / PaaS Hosting Abuse:** Modern attackers host credential harvesting attacks on free cloud application subdomains (`pages.dev`, `netlify.app`, `github.io`, `vercel.app`, `firebaseapp.com`, `render.com`).
3. **Link Count Decoupling:** Because production tree splits treated high link counts as a strong indicator of legitimacy, cloned phishing attacks on PaaS subdomains bypassed detection.

### 8.2 Intervention Design (Candidate Exp 3)
- **Feature Isolated:** Added `is_free_hosting_subdomain` (44 features total).
- **Hypothesis:** Adding an explicit structural indicator for free application hosting subdomains allows the decision trees to identify high-link cloned attacks without relying exclusively on low link counts.
- **Training Integrity:** Exact production hyperparameters (`learning_rate=0.05, n_estimators=200, max_depth=4, colsample_bytree=0.7, subsample=0.95, reg_lambda=1.0, scale_pos_weight=5.0, seed=42`).
- **Artifact:** `candidate_exp3_paas_signal.joblib` (SHA-256 `41761e991d9fd194d6ff2716566fa68694cba100ce337e8fce575c7ee0216e3f`).

### 8.3 Outcome & Governance
- **Recall Floor:** Achieved **94.46% (375/397)**, successfully exceeding the $\ge 94.0\%$ safety floor (+0.25% gain).
- **False Negative Recovery:** Recovered 2 high-link cloned attacks (`avocent.netlify.app` and `da51ca.pages.dev`).
- **Governance:** In accordance with project policy, the experimental artifact is recorded as a qualified promotion candidate, but **Current Production (`7a80ec64...`) remains active** pending explicit human authorization.

