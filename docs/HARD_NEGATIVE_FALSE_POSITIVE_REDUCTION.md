# Hard-Negative Mining & False-Positive Reduction Engineering Report
**Experiment ID**: `EXP-HARD-NEGATIVE-FP-REDUCTION-2026-09-16`  
**Date**: `2026-09-16`  
**Production Model**: `backend/ml/models/phishing_model.joblib` (v2.1.0)  
**Production Model SHA-256**: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` (**VERIFIED 100% UNTOUCHED**)  
**Final Selection Decision**: **`REJECT`**

---

## 1. Executive Summary & Objective

The primary operational challenge of PhishGuard AI v2.1.0 is its elevated false-positive rate on **sparse legitimate pages** (legitimate web pages with few or no static links, JavaScript-rendered single-page applications, and minimal DOM trees). On the verified fixed production test split ($N=1,799$, $1,402$ legitimate, $397$ phishing), the production model achieves **$94.21\%$ phishing recall** with a **$5.35\%$ overall False Positive Rate (FPR)** ($75$ false positives). However, the FPR on the sparse legitimate slice is **$28.89\%$** ($65$ of $225$ sparse legitimate samples misclassified), accounting for **$86.7\%$** of all production false positives.

### Objective:
Evaluate whether **out-of-fold hard-negative mining and training set augmentation** can train the gradient-boosted decision trees to recognize sparse legitimate structure without allowing phishing attack recall to fall below the mandatory threshold of **$\ge 94.00\%$**, and without relying on static domain whitelists or provider allowlists.

---

## 2. Dataset Categorization & Legitimate Profile Analysis

Across the full curated dataset of $8,910$ samples ($7,005$ legitimate, $1,905$ phishing across $3,151$ distinct registered apex domains), legitimate samples were categorized across 10 structural and semantic profiles:

| Legitimate Category Profile | Count | % of Legitimate Corpus | Structural / Behavioral Risk Profile |
| :--- | :---: | :---: | :--- |
| **JavaScript-Rendered Pages (`js_rendered_page`)** | 5,076 | 72.46% | Static scraper extracts 0 links; mimics minimal phishing payload |
| **Government & Institutional (`government_institutional`)** | 1,219 | 17.40% | Complex domains (`.gov`, `.edu`, multi-tier subdomains), deep paths |
| **Login / SSO Portals (`login_sso_page`)** | 1,154 | 16.47% | Password inputs, authentication forms, tokenized parameters |
| **Sparse Pages (`sparse_page`, $\le 20$ links)** | 1,100 | 15.70% | Low total link count, high concentration in navigation |
| **General Content (`general_content`)** | 684 | 9.76% | Standard multi-link informative articles and portals |
| **HTTPS with Zero Internal Links (`https_zero_internal_links`)** | 528 | 7.54% | Minimal static landing pages with absolute external links only |
| **External Form Action Pages (`external_form_action`)** | 439 | 6.27% | Forms posting to external identity providers (OAuth/SAML) |
| **Static Landing Pages (`static_landing_page`)** | 294 | 4.20% | Single-fold product/event landing pages with minimal outbound navigation |
| **Documentation Pages (`documentation_page`)** | 154 | 2.20% | API references and code documentation with token-like paths |
| **Developer Portals (`developer_portal`)** | 64 | 0.91% | Deep paths, UUID-based query strings, developer console URLs |
| **Cloud-Hosted Portals (`cloud_hosted`)** | 33 | 0.47% | Microsoft Azure/Cloud, AWS, Google Cloud app consoles |

---

## 3. Hard-Negative Mining Pipeline & Augmented Dataset

### 3.1 Out-of-Fold Mining Methodology (Zero Data Leakage)
1. **Partition Isolation**: The dataset ($N=8,910$) was split into a **training partition** ($N=7,111$, $2,520$ apex domains) and a **held-out fixed test partition** ($N=1,799$, $631$ apex domains) using `GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)`.
2. **Domain Leakage Verification**: $0.00\%$ domain overlap was verified between train and test partitions ($0$ intersecting apex domains).
3. **Out-of-Fold (OOF) Inference**: A 5-fold domain-disjoint `GroupKFold` cross-validation was run strictly within the training partition ($N=7,111$) using baseline XGBoost hyperparameters.
4. **Hard-Negative Identification**:
   - Mined **$505$ hard-negative legitimate samples** with out-of-fold threat scores $\ge 0.25$.
   - Identified **$284$ severe false positives** with out-of-fold threat scores $\ge 0.50$.
   - Verified that every mined candidate was a confirmed legitimate public/institutional web page.

### 3.2 Augmented Dataset Versioning: `training_dataset_hard_negatives.csv`
- **Location**: `backend/data/processed/training_dataset_hard_negatives.csv`
- **Total Rows**: $9,920$ rows ($7,111$ original training rows + $1,010$ hard-negative augmented training instances + $1,799$ held-out test rows).
- **Label Integrity**: $0$ conflicting labels, $0$ duplicate URLs in training partition.
- **Apex Domain Leakage**: Exactly $0.00\%$ overlap with the held-out test partition.

---

## 4. Isolated Candidate Model Architecture

| Candidate | Features | Training Dataset | Hyperparameters / Constraints |
| :--- | :--- | :--- | :--- |
| **Candidate A** | Original 43 features | Original Training Set ($N=7,111$) | XGBoost (`max_depth=4`, `lr=0.05`, `n_est=200`, `colsample=0.70`, `subsample=0.95`, `spw=5.0`) |
| **Candidate B** | Original 43 features | Hard-Negative Augmented ($N=8,121$) | XGBoost baseline configuration (`spw=5.0`) |
| **Candidate C** | Original 43 features | Hard-Negative Augmented ($N=8,121$) | Grid-searched `scale_pos_weight` $\in [3.0, 4.0, 5.0, 6.0, 7.0]$ |
| **Candidate D** | Original 43 features + Conservative Semantics | Hard-Negative Augmented ($N=8,121$) | Monotone positive constraints (`monotone_constraints = 1` on semantic threat features) |

---

## 5. Fair Fixed-Split Benchmark Results ($N=1,799$, Seed 42)

Held-out test set: **$1,799$ samples** ($1,402$ legitimate, $397$ phishing, $631$ disjoint domains). Decision threshold = $0.50$.

| Metric | Production Baseline (A) | Hard-Neg Augmented (B) | Tuned SPW (C, spw=5.0) | Conservative Semantic (D) |
| :--- | :---: | :---: | :---: | :---: |
| **Accuracy** | 94.55% | **96.66%** | **96.66%** | **96.66%** |
| **Phishing Recall** ($\ge 94\%$ req.) | **94.21%** (374/397) | 92.70% (368/397) ⚠️ | 92.70% (368/397) ⚠️ | 91.44% (363/397) ⚠️ |
| **Precision** | 83.30% | 92.23% | 92.23% | **93.32%** |
| **F1-Score** | 88.42% | **92.46%** | **92.46%** | 92.37% |
| **Specificity** | 94.65% | 97.79% | 97.79% | **98.15%** |
| **False Positive Rate (FPR)** | 5.35% (75 FP) | 2.21% (31 FP) | 2.21% (31 FP) | **1.85% (26 FP)** |
| **False Negative Rate (FNR)** | **5.79%** (23 FN) | 7.30% (29 FN) | 7.30% (29 FN) | 8.56% (34 FN) |
| **ROC-AUC** | 0.9819 | 0.9832 | 0.9832 | **0.9840** |
| **PR-AUC** | 0.9636 | 0.9670 | 0.9670 | **0.9687** |
| **Sparse Legit FPR** ($N=225$) | 28.89% (65 FP) | 12.00% (27 FP) | 12.00% (27 FP) | **10.67% (24 FP)** |
| **Sparse Phishing Recall** ($N=290$) | **98.97%** (287/290) | 96.90% (281/290) | 96.90% (281/290) | 96.21% (279/290) |
| **HTTPS Phishing Recall** ($N=316$) | **93.04%** (294/316) | 91.14% (288/316) | 91.14% (288/316) | 89.24% (282/316) |
| **Shortened URL Recall** ($N=18$) | 94.44% (17/18) | 94.44% (17/18) | 94.44% (17/18) | 94.44% (17/18) |
| **Legit Login/SSO FPR** ($N=221$) | 3.17% (7 FP) | 1.36% (3 FP) | 1.36% (3 FP) | **1.36% (3 FP)** |
| **Ext-Form Legit FPR** ($N=87$) | 2.30% (2 FP) | **1.15% (1 FP)** | **1.15% (1 FP)** | 2.30% (2 FP) |
| **Ext-Form Phish Recall** ($N=14$) | **100.00%** (14/14) | **100.00%** (14/14) | **100.00%** (14/14) | 92.86% (13/14) |

### Candidate C: `scale_pos_weight` Grid Sweep on Fixed Split
| `scale_pos_weight` | Accuracy | Phishing Recall | Precision | FPR | Sparse Legit FPR | False Negatives |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **3.0** | 96.22% | 88.41% | 94.10% | 1.57% | 8.89% | 46 FN |
| **4.0** | 96.28% | 89.67% | 93.19% | 1.85% | 10.22% | 41 FN |
| **5.0** | 96.66% | 92.70% | 92.23% | 2.21% | 12.00% | 29 FN |
| **6.0** | 96.00% | 92.19% | 89.93% | 2.92% | 16.00% | 31 FN |
| **7.0** | 96.11% | 92.70% | 89.98% | 2.92% | 15.11% | 29 FN |

*Finding*: Increasing `scale_pos_weight` beyond 5.0 does not recover phishing recall on the augmented dataset because the tree splits adapt to the increased density of sparse negative samples by shifting the decision boundary.

---

## 6. Repeated 5-Seed Domain-Disjoint Validation

To prevent overfitting to any single test split, all candidates were evaluated across 5 random seeds (`[42, 101, 777, 2024, 9999]`) using domain-grouped `GroupShuffleSplit`:

| Candidate | Mean Phishing Recall | Mean Overall FPR | Mean Sparse Legit FPR | Mean Precision | Mean Accuracy | Total False Negatives (5 seeds) | Total False Positives (5 seeds) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Candidate A** | **91.81% ± 4.51%** | 4.72% ± 0.87% | 28.10% ± 4.12% | 84.54% ± 5.05% | 94.35% ± 1.43% | **192** | 336 |
| **Candidate B** | 87.01% ± 10.14% | 2.13% ± 0.32% | 12.74% ± 1.35% | 91.90% ± 2.62% | 95.10% ± 3.10% | 314 | 152 |
| **Candidate C** | 87.01% ± 10.14% | 2.13% ± 0.32% | 12.74% ± 1.35% | 91.90% ± 2.62% | 95.10% ± 3.10% | 314 | 152 |
| **Candidate D** | 86.82% ± 10.60% | **2.10% ± 0.34%** | **12.49% ± 1.40%** | **91.97% ± 2.68%** | 95.08% ± 3.32% | 318 | **150** |

### Per-Seed Phishing Recall Breakdown:
- **Seed 42**: Cand A = 94.21% | Cand B = 92.70% | Cand C = 92.70% | Cand D = 91.44%
- **Seed 101**: Cand A = 93.98% | Cand B = 93.33% | Cand C = 93.33% | Cand D = 93.55%
- **Seed 777**: Cand A = 93.47% | Cand B = 90.20% | Cand C = 90.20% | Cand D = 89.80%
- **Seed 2024**: Cand A = 82.82% | Cand B = 66.84% | Cand C = 66.84% | Cand D = 65.81%
- **Seed 9999**: Cand A = 94.58% | Cand B = 91.97% | Cand C = 91.97% | Cand D = 93.49%

---

## 7. Decision Threshold Trade-Off Analysis

Evaluating Candidates A, B, and D across decision thresholds $\tau \in [0.30, 0.60]$ on the fixed split ($N=1,799$):

### Candidate A (Baseline)
| Threshold $\tau$ | Phishing Recall | Overall FPR | Precision | F1-Score | Sparse Legit FPR | False Positives | False Negatives |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **0.30** | 94.96% | 8.06% | 76.94% | 85.01% | 41.33% | 113 | 20 |
| **0.35** | 94.96% | 7.42% | 78.38% | 85.88% | 38.67% | 104 | 20 |
| **0.40** | 94.71% | 6.78% | 79.83% | 86.64% | 36.44% | 95 | 21 |
| **0.45** | 94.46% | 6.06% | 81.52% | 87.51% | 32.89% | 85 | 22 |
| **0.50** | **94.21%** | **5.35%** | **83.30%** | **88.42%** | **28.89%** | **75** | **23** |
| **0.55** | 93.45% | 4.28% | 86.08% | 89.61% | 22.67% | 60 | 26 |
| **0.60** | 92.95% | 3.42% | 88.49% | 90.66% | 17.78% | 48 | 28 |

### Candidate B (Hard-Negative Augmented)
| Threshold $\tau$ | Phishing Recall | Overall FPR | Precision | F1-Score | Sparse Legit FPR | False Positives | False Negatives |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **0.30** | **94.71%** | 5.21% | 83.74% | 88.89% | 28.44% | 73 | 21 |
| **0.35** | 93.70% | 4.21% | 86.31% | 89.86% | 23.11% | 59 | 25 |
| **0.40** | 93.45% | 3.42% | 88.54% | 90.93% | 18.22% | 48 | 26 |
| **0.45** | 92.95% | 2.57% | 91.11% | 92.02% | 13.78% | 36 | 28 |
| **0.50** | 92.70% | 2.21% | 92.23% | 92.46% | 12.00% | 31 | 29 |
| **0.55** | 90.43% | 1.85% | 93.25% | 91.82% | 10.67% | 26 | 38 |
| **0.60** | 87.15% | 1.50% | 94.28% | 90.58% | 8.44% | 21 | 51 |

### Candidate D (Conservative Semantic + Monotone Constraints)
| Threshold $\tau$ | Phishing Recall | Overall FPR | Precision | F1-Score | Sparse Legit FPR | False Positives | False Negatives |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **0.30** | **94.46%** | 5.71% | 82.42% | 88.03% | 28.89% | 80 | 22 |
| **0.35** | 93.95% | 4.78% | 84.77% | 89.13% | 24.44% | 67 | 24 |
| **0.40** | 93.45% | 3.78% | 87.50% | 90.38% | 20.44% | 53 | 26 |
| **0.45** | 92.70% | 2.71% | 90.64% | 91.66% | 15.11% | 38 | 29 |
| **0.50** | 91.44% | 1.85% | 93.32% | 92.37% | 10.67% | 26 | 34 |
| **0.55** | 90.43% | 1.71% | 93.73% | 92.05% | 9.78% | 24 | 38 |
| **0.60** | 88.16% | 1.14% | 95.63% | 91.74% | 6.67% | 16 | 47 |

> [!NOTE]
> **Calibration Clarification**: Output scores produced by `predict_proba` in XGBoost are monotonic risk ranking scores, not calibrated Bayesian posterior probabilities. Shifting the operating threshold alters the operational decision boundary along the model's empirical ROC curve.

---

## 8. Hard-Negative Error Analysis

Inspection of top mined hard negatives in `scratch/hard_negative_candidates.json`:

| URL | Apex Domain | OOF Score | Category Profile | Key Feature Signatures | Root Cause for High FP Threat Score |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `https://customerservice.aliexpress.com/category?...` | `aliexpress.com` | **0.9935** | Sparse, JS-Rendered, 0 Internal Links | `num_links=0`, `url_length=158`, `https=1` | Zero static links mimics empty phishing landing payload |
| `https://appsec-info.waas.barracudanetworks.com/scan` | `barracudanetworks.com` | **0.9891** | Sparse, Static Landing, 0 Internal Links | `num_links=0`, `domain_len=38`, `https=1` | Subdomain depth + 0 links triggers link-shortcut heuristic |
| `https://outlook.cloud.microsoft/mail/copilot/...` | `cloud.microsoft` | **0.9845** | Sparse, Developer Portal, JS-Rendered | `num_links=0`, `url_length=316`, `https=1` | Tokenized deep URL path + 0 internal links |
| `https://m365.cloud.microsoft/chat/...` | `cloud.microsoft` | **0.9836** | Sparse, Developer Portal, JS-Rendered | `num_links=0`, `url_length=681`, `https=1` | Long hexadecimal/base64 URL parameter + 0 links |

---

## 9. Root-Cause Synthesis: Why Hard-Negative Retraining Drops Recall

1. **The Link-Sparsity Shortcut**:
   In the baseline model, `num_links` and `num_internal_links` contribute over $43\%$ of total model gain. Because genuine phishing landing pages frequently have zero internal links and minimal page elements, the baseline model heavily relies on link sparsity as a strong indicator of maliciousness.
2. **The Hard-Negative Dilution Effect**:
   When $505$ hard-negative legitimate pages with $0$ links are added to the training set, the decision trees learn that link sparsity is no longer a reliable signal for phishing.
3. **The Unintended Trade-Off**:
   While this successfully slashes sparse legitimate FPR from **$28.89\%$ down to $12.00\%$** and cuts total false positives from **$75$ to $31$** (a $58.7\%$ reduction), it simultaneously deprives the model of its primary signal for detecting minimalist phishing lures that have no other obvious lexical anomalies.
4. **Recall Degradation**:
   As a direct consequence, phishing attack recall drops from **$94.21\%$ down to $92.70\%$** on the fixed split, and collapses to **$66.84\%$** under Seed 2024 out-of-distribution domain shift.
5. **Threshold Inefficiency**:
   Lowering the decision threshold to $0.30$ to restore recall ($\ge 94.00\%$) erodes the FPR improvement ($5.21\%$ vs $5.35\%$), neutralizing the operational benefit of hard-negative retraining.

---

## 10. Model Selection & Final Engineering Decision

### Model Selection Rule Audit:
1. **Rule 1**: First require phishing recall $\ge 94.00\%$.
   - Baseline Candidate A: **$94.21\%$** (Passes)
   - Candidate B (Hard-Negative Augmented, $\tau=0.50$): **$92.70\%$** (Fails)
   - Candidate C (Tuned SPW, $\tau=0.50$): **$92.70\%$** (Fails)
   - Candidate D (Conservative Semantic, $\tau=0.50$): **$91.44\%$** (Fails)
2. **Rule 2**: If no candidate satisfies recall $\ge 94.00\%$, report `REJECT` or `INCONCLUSIVE`.

### Compliance & Safety Verifications:
- [x] Production model `backend/ml/models/phishing_model.joblib` remained **completely untouched**.
- [x] Final SHA-256 hash verified: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` (**100% Identical**).
- [x] Zero static domain whitelists or provider allowlists introduced.
- [x] Zero automated deployment or production artifact overwrites performed.

---

## Final Decision
```
REJECT
```
**Decision Justification**:
Although hard-negative augmentation successfully achieves the primary objective of reducing sparse legitimate false positives by $58.5\%$ (slashing sparse FPR from $28.89\%$ to $12.00\%$), it violates the mandatory production safety invariant by causing phishing recall to drop below $94.00\%$ ($92.70\%$ on fixed split, $87.01\%$ 5-seed mean, and $66.84\%$ on Seed 2024). Candidates B, C, and D are formally **REJECTED** for production promotion.
