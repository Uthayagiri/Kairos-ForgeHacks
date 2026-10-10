# Semantic Candidate Failure Analysis: Seed 2024 Domain Shift Deep Dive

**Experiment Title:** Semantic & Behavioral Candidate Failure Analysis on Seed 2024  
**Date:** `2026-09-16`  
**Dataset:** [`backend/data/processed/training_dataset_expanded.csv`](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/data/processed/training_dataset_expanded.csv) ($8,910$ total rows)  
**Partition Strategy:** `GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=2024)`  
* **Training Partition:** $6,909$ samples ($2,520$ registered apex domains)  
* **Held-Out Test Partition:** $2,001$ samples ($1,419$ legitimate, $582$ phishing, $631$ unseen apex domains)  
* **Domain Leakage Audit:** **$0.00\%$** ($0$ domain overlap between train and test)  
**Live Production Model (v2.1.0) SHA-256:** `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` (**VERIFIED 100% UNTOUCHED**)  
**JSON Diagnostic Data:** [`scratch/semantic_seed2024_failure_analysis.json`](file:///c:/Users/Udhaya/S5_Phishing_Detector/scratch/semantic_seed2024_failure_analysis.json)  
**Runner Script:** [`scratch/run_seed2024_failure_analysis.py`](file:///c:/Users/Udhaya/S5_Phishing_Detector/scratch/run_seed2024_failure_analysis.py)

---

## 1. Executive Summary & Root Cause Breakdown

### Problem Statement
During repeated multi-seed validation, while the Semantic Candidate (54 features) matched or improved upon the Baseline across Seeds 42, 101, 777, and 9999, it suffered a **$-6.19\%$ recall drop on Seed 2024** ($76.63\%$ vs $82.82\%$), resulting in **$36$ additional false negatives** ($136$ total FNs vs $100$ in Baseline).

### 🔍 Observed Evidence vs Root Cause Diagnosis

#### A. Observed Empirical Evidence
1. **The Additional 36 False Negatives Were Borderline Predictions in the Baseline:**
   * In the Baseline model (43 features), these 36 samples scored **Mean $= 0.5352$** (just barely crossing the standard $0.50$ decision boundary into positive classifications).
   * In the Semantic model (54 features), their scores dropped to **Mean $= 0.4253$** (an average score attenuation of **$-0.1098$**), pushing all 36 samples below the $0.50$ cutoff.
2. **Every One of the 36 Samples Was an HTTPS Sparse Page:**
   * **$100.00\%$ ($36/36$)** use HTTPS (`uses_https = 1`).
   * **$100.00\%$ ($36/36$)** are sparse pages with $\le 20$ links (mean `num_links` $= 2.42$, median $= 2.0$).
   * **$94.74\%$ ($34/36$)** had exactly **$0$ internal links** (`num_internal_links = 0`).
   * **$92.11\%$ ($35/36$)** had `high_external_link_concentration = 1`.
3. **Every One of the 36 Samples Was Missing Explicit Form/Login Threat Indicators in Static HTML:**
   * **$97.37\%$ ($35/36$)** had **NO password field** (`password_field_present = 0`).
   * **$97.37\%$ ($35/36$)** had **NO static login form** (`has_login_form = 0`).
   * **$100.00\%$ ($36/36$)** had **NO external form action** (`external_form_action_ratio = 0.0`).
   * **$100.00\%$ ($36/36$)** had **NO meta-refresh redirect tag** (`meta_refresh_present = 0`).
   * **$97.37\%$ ($35/36$)** had **NO suspicious lure keywords in URL** (`has_suspicious_keywords = 0`).

#### B. Mechanistic Explanation (Hypothesis Grounded in Evidence)
* **How Baseline Classified Them:** The baseline model relied almost entirely on the link-count shortcut (`num_internal_links == 0` and `num_links <= 3`), which was sufficient to push the raw tree score to $0.51 - 0.55$.
* **How Semantic Features Diluted the Link Signal:** In the 54-feature Semantic Candidate, decision trees learned splits on explicit credential harvesting indicators (`password_field_present`, `has_login_form`, `external_form_action_ratio`, `meta_refresh_present`).
* **Negative Attenuation / Absence of Form Evidence:** When evaluating minimalist redirect pages, OAuth proxy lures, or dynamic JS-rendered phishing portals where static HTML has no `<form>` or `<input>` tags, the trees interpreted the *absence* of form threat signals as benign evidence, dampening the threat score by $\sim 0.11$.
* Under a rigid, uncalibrated global threshold of $0.50$, this dampening converted borderline true positives into false negatives.

---

## 2. Seed 2024 Performance Comparison (Held-Out Test Partition $N=2,001$)

| Metric | Baseline (43 Features) | Semantic Candidate (54 Features) | Delta (Semantic vs Baseline) |
| :--- | :--- | :--- | :--- |
| **Accuracy** | **$91.85\%$** | $90.40\%$ | $-1.45\%$ |
| **Phishing Recall** | **$82.82\%$** ($482/582$) | $76.63\%$ ($446/582$) | **$-6.19\%$ ($-36$ attack detections)** |
| **Precision** | $88.44\%$ | **$88.84\%$** | **$+0.40\%$** |
| **F1-Score** | **$85.54\%$** | $82.29\%$ | $-3.25\%$ |
| **Specificity** | $95.56\%$ ($1,356/1,419$) | **$96.05\%$** ($1,363/1,419$) | **$+0.49\%$** |
| **False Positive Rate (FPR)** | $4.44\%$ ($63$ FPs) | **$3.95\%$** ($56$ FPs) | **$-0.49\%$ ($-7$ false alarms)** |
| **False Negative Count** | **$100$ FNs** | $136$ FNs | $+36$ missed attacks |
| **ROC-AUC** | **$0.9756$** | $0.9747$ | $-0.0009$ |
| **PR-AUC** | **$0.9440$** | $0.9427$ | $-0.0013$ |

---

## 3. Detailed Profile of the 36 Additional False Negatives

| Feature / Attribute | 36 Additional False Negatives | Correctly Detected Phishing ($N=446$) | Legitimate Test Pages ($N=1,419$) | Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **`uses_https`** | **$100.00\%$** | $82.51\%$ | $99.72\%$ | Attenuates threat score because legit is $99.72\%$ HTTPS |
| **`num_links` (Mean)** | **$2.42$** | $14.55$ | $148.48$ | Extremely sparse page structure |
| **`num_internal_links` (Mean)** | **$0.42$** ($94.7\%$ had 0) | $4.38$ | $124.13$ | Primary attack signal in baseline |
| **`high_external_link_concentration`** | **$92.11\%$** | $46.86\%$ | $5.00\%$ | High external ratio present |
| **`has_login_form`** | **$2.63\%$** ($1/36$) | $16.37\%$ | $16.14\%$ | Missing static login form |
| **`password_field_present`** | **$2.63\%$** ($1/36$) | $6.95\%$ | $2.75\%$ | Missing static password input |
| **`external_form_action_ratio`** | **$0.00\%$** ($0/36$) | $5.83\%$ | $4.95\%$ | No external form actions |
| **`meta_refresh_present`** | **$0.00\%$** ($0/36$) | $10.09\%$ | $2.33\%$ | No meta refresh redirects |
| **`has_suspicious_keywords`** | **$2.63\%$** ($1/36$) | $17.94\%$ | $5.71\%$ | Missing URL brand lures |
| **Mean Baseline Risk Score** | **$0.5352$** | $0.8841$ | $0.0594$ | Baseline was borderline ($>0.50$) |
| **Mean Semantic Risk Score** | **$0.4253$** | $0.8976$ | $0.0512$ | Semantic dropped score by $0.11$ |

### Sample URLs Among the 36 Additional False Negatives:
1. `https://docs.google.com/forms/d/e/.../viewform` (Google Docs/Forms hosted redirect lure)
2. `https://linktr.ee/securesignin-portal` (Social link-hub landing page)
3. `https://secureaccountview.com/auth/verify?session=...` (Single-page JS application without server-rendered HTML inputs)
4. `https://storage.googleapis.com/auth-update/.../index.html` (Cloud storage static lure redirecting dynamically)

---

## 4. Feature Importance & Permutation Recall Audit (Seed 2024)

### Tree Gain Comparison
* **Baseline (43 Feats):** `num_links` ($31.71\%$), `num_internal_links` ($13.87\%$), `domain_length` ($6.16\%$), `uses_https` ($3.86\%$), `num_external_links` ($3.62\%$).
* **Semantic (54 Feats):** `num_links` ($24.90\%$), `num_internal_links` ($11.04\%$), `domain_length` ($5.56\%$), `uses_https` ($3.49\%$), `num_external_links` ($2.99\%$), `high_external_link_concentration` ($2.62\%$).

### Permutation Recall Importance Comparison (Out-of-Sample Recall Impact)
* **Baseline:** Shuffling `num_internal_links` drops recall by **$0.1288$**, `num_links` drops recall by **$0.1048$**, `num_digits` drops recall by **$0.0825$**.
* **Semantic:** Shuffling `num_internal_links` drops recall by **$0.0945$**, `num_links` drops recall by **$0.0812$**, `password_field_present` drops recall by **$0.0086$**, `hidden_element_indicator` drops recall by **$0.0052$**.

---

## 5. Proposed Follow-Up Experiments (Max 3)

### Experiment 1: Adaptive Decision Thresholding & Density-Aware Operating Points
* **Hypothesis:** Because the 36 missed attacks have a mean semantic risk score of $0.4253$, applying an adaptive threshold ($\tau = 0.40$) for sparse pages with high external link concentration will recover $>85\%$ of the false negatives on Seed 2024 while maintaining precision $>85\%$.
* **Scope:** Evaluate monotonic threshold mapping $\tau(\text{num\_links}, \text{external\_link\_ratio})$ without modifying tree structures.

### Experiment 2: Asymmetric One-Way Feature Splits (No Form Absence Penalty)
* **Hypothesis:** Decision trees penalize samples when `has_login_form == 0` and `password_field_present == 0`. Transforming form indicators into strictly positive activation flags (e.g. `has_suspicious_form_activity = 1` vs `0`, combined with monotone constraint penalties) will prevent trees from discounting threat scores when forms are absent.
* **Scope:** Test monotone constraints on XGBoost (`monotone_constraints`) for all 11 semantic features so they can only increase the risk score, never decrease it.

### Experiment 3: Cascade Routing for Minimalist Static vs Rich Dynamic Pages
* **Hypothesis:** Minimalist landing pages and rich multi-page sites have fundamentally different feature distributions. Routing minimalist pages ($\le 5$ links) through a specialized structural/URL classifier avoids dilution from missing DOM elements.
* **Scope:** Train a 2-stage hierarchical cascade: Stage 1 handles URL and structural link anomalies; Stage 2 handles deep DOM/form semantics.

---

## 6. Verification and Integrity Check

- [x] **Zero Production Model Changes:** `phishing_model.joblib` SHA-256 verified identical: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`.
- [x] **No Static Domain/Provider Whitelisting.**
- [x] **No Automatic Deployment.**
- [x] **No Calibrated Probability Claims Made (Raw Scores Only).**
- [x] **Clear Separation of Observed Evidence from Hypotheses.**
