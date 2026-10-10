# PhishGuard AI — Machine Learning Pipeline & Dataset Audit

## 1. Model Artifact & Architecture Details

The active machine learning component in PhishGuard AI was audited via its persisted artifacts in `backend/ml/models/`:

- **Production Model File:** `backend/ml/models/phishing_model.joblib`
- **Model Size:** 321,430 bytes (~314 KB)
- **Model Version:** `2.1.0` (Candidate A4 Champion)
- **Model Architecture:** `xgboost.XGBClassifier` (XGBoost v2.1.0)
- **SHA-256 Integrity Hash:** `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`
- **Feature Vector Dimension:** 43 tabular columns (22 URL lexical, 21 HTML structural)

### Hyperparameter Configuration
```json
{
  "n_estimators": 200,
  "max_depth": 4,
  "learning_rate": 0.05,
  "subsample": 0.95,
  "colsample_bytree": 0.7,
  "reg_lambda": 1.0,
  "scale_pos_weight": 5.0
}
```

---

## 2. Dataset Provenance, Composition & Leakage Audit

### Dataset Overview (`backend/data/processed/training_dataset_expanded.csv`)
- **Total Samples:** 8,910 samples
- **Training Partition:** 7,111 samples (79.8%)
- **Held-Out Test Partition:** 1,799 samples (20.2%)
- **Unique Registered Domains:** 3,151 distinct root domains
- **Training Domains:** 2,520 domains
- **Testing Domains:** 631 domains
- **Domain Overlap Leakage:** **0.00%**

### Provenance & Class Balance
1. **Benign Class (`label = 0` / Legitimate):**
   - Sourced from Tranco / Alexa Top 1M domains, expanded via deep internal link crawlers (`crawl_legitimate_deep_links.py`) and diverse regional collections (`diversify_legitimate_dataset.py`) to prevent domain-only bias.
2. **Phishing Class (`label = 1` / Malicious):**
   - Sourced from PhishTank verified active feeds and OpenPhish repository archives.
3. **Class Distribution in Held-Out Test Set:**
   - True Negatives: 1,327 (Legitimate)
   - True Positives: 374 (Phishing)
   - Class Ratio: ~3.5:1 benign-to-phishing ratio in the evaluation split.

### Domain Leakage Assessment
In naive phishing ML papers, multiple URLs from the same domain (e.g. `google.com/search`, `google.com/maps`, `google.com/drive`) are randomly split across train and test sets, causing artificial test performance inflation of 99%+ accuracy.  
**Auditor Verification:** The training script ([deploy_candidate_a4.py](file:///c:/Users/Udhaya/S5_Phishing_Detector/scratch/deploy_candidate_a4.py)) uses `sklearn.model_selection.GroupShuffleSplit` grouping on `reg_domain`. No domain appearing in the training set appears in the held-out evaluation set. **This is a verified, scientifically rigorous methodology.**

---

## 3. Performance Metrics: Claims vs. Evaluation Evidence

### Held-Out Evaluation Split (`test_samples = 1,799`)

| Metric | Metadata Claim | Verified Test Value | Auditor Evaluation |
| :--- | :---: | :---: | :--- |
| **Accuracy** | 94.55% | **0.9455** | Supported by confusion matrix |
| **Precision** | 83.30% | **0.8330** | 374 / (374 + 75) = 83.296% |
| **Recall (Sensitivity)** | 94.21% | **0.9421** | 374 / (374 + 23) = 94.206% |
| **F1 Score** | 0.8842 | **0.8842** | Harmonic mean of 0.8330 and 0.9421 |
| **ROC AUC** | 0.9819 | **0.9819** | Strong class separability on test split |
| **Brier Score** | 0.0390 | **0.0390** | Mean squared difference from true binary labels |

### Confusion Matrix Breakdown
```
                       Actual Benign (0)    Actual Phishing (1)
Predicted Benign (0)         1,327 (TN)             23 (FN)
Predicted Phishing (1)          75 (FP)            374 (TP)
```
- **False Negative Rate (FNR):** 23 / 397 = **5.79%** (Attack misses)
- **False Positive Rate (FPR):** 75 / 1,402 = **5.35%** (Benign false alarms)

---

## 4. Critical ML Flaws & Feature Dominance Analysis

### Top 15 Feature Importances (Gini / Gain Splits)

| Rank | Feature Name | Source | Importance Weight | Cumulative Weight |
| :---: | :--- | :---: | :---: | :---: |
| **1** | `num_links` | HTML | **26.47%** | 26.47% |
| **2** | `num_internal_links` | HTML | **16.59%** | **43.06%** |
| **3** | `num_external_links` | HTML | 6.54% | 49.60% |
| **4** | `domain_length` | URL | 4.80% | 54.40% |
| **5** | `uses_https` | URL | 3.58% | 57.98% |
| **6** | `external_link_ratio` | HTML | 3.03% | 61.01% |
| **7** | `path_length` | URL | 2.55% | 63.56% |
| **8** | `num_digits` | URL | 2.35% | 65.91% |
| **9** | `num_slashes` | URL | 2.29% | 68.20% |
| **10**| `path_depth` | URL | 1.96% | 70.16% |
| **11**| `num_subdomains` | URL | 1.88% | 72.04% |
| **12**| `num_dots` | URL | 1.77% | 73.81% |
| **13**| `num_iframes` | HTML | 1.67% | 75.48% |
| **14**| `url_length` | URL | 1.63% | 77.11% |
| **15**| `has_login_form` | HTML | 1.51% | 78.62% |

### Severe Structural Vulnerability: The "Low Link Count" Bias
Notice that **`num_links` and `num_internal_links` alone account for 43.06% of the model's predictive weight!**
- In classic phishing datasets, attackers clone a single credential harvest page with minimal navigation, yielding 0–5 links, whereas benign corporate websites (Amazon, CNN, Wikipedia) feature 100+ navigation links.
- Because the model learns this raw count correlation, **ANY webpage with few links is heavily penalized as a probable phishing site**.
- This creates severe false-positive vulnerabilities on:
  1. Single Page Applications (SPAs) before client JavaScript renders.
  2. Minimalist portfolio and product landing pages.
  3. Single-purpose enterprise login pages (e.g. corporate SSO or intranet sign-in portals).
  4. Newly launched startup sites.

---

## 5. Probability Calibration & Score Misrepresentation

In `backend/ml/models/model_metadata.json`, the authors include an honest disclosure:
> *"This model intentionally uses scale_pos_weight=5.0 and feature subsampling (colsample_bytree=0.7) to maximize attack recall (94.21%) and prevent link count dominance. Output scores represent monotonic risk scores / ordinal threat indicators (higher score = more suspicious), rather than calibrated empirical probabilities."*

### Why the Displayed Percentage is NOT an Empirical Probability
1. Setting `scale_pos_weight = 5.0` artificially penalizes false negatives by 5x during tree boosting. This shifts the decision boundary heavily toward the positive class.
2. An output of `confidence = 0.92` (92%) **does not mean** there is a 92% statistical likelihood that the site is phishing. It means the model's skewed decision function produced an ordinal threat score of 92 on a 0–100 scale.
3. The web dashboard and extension display this score as:
   `Risk Score: 92%` or `Gauge: 92%`
4. Presenting this to end users as a literal percentage risk can mislead security teams into believing the system possesses calibrated Bayesian certainty.

---

## 6. Training vs. Inference Pipeline Consistency

The auditor compared the feature generation logic in `ml/training/build_training_dataset.py` with `app/services/detection_engine.py`:
- Column ordering is strictly governed by `backend/ml/models/feature_columns.json`.
- Missing values in offline training were zero-filled for boolean/count features, matching `get_default_feature_dict()` and `get_default_html_feature_dict()` during runtime inference.
- Boolean flags are consistently coerced to integer `0` / `1` in both pipelines.
- **Verdict:** Training and inference feature schemas are **100% synchronized and free of column mismatch defects**.
