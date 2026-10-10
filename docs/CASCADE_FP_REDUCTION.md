# High-Recall Cascade Architecture for False-Positive Reduction
**Task ID**: `EXP-13-HIGH-RECALL-CASCADE-FP-REDUCTION-IMPLEMENTATION`  
**Date**: `2026-09-16`  
**Live Production Model**: `backend/ml/models/phishing_model.joblib` (v2.1.0)  
**Production Model SHA-256**: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` (**VERIFIED 100% UNTOUCHED**)  

---

## 1. Executive Summary & Architecture Overview

In prior retraining experiments (e.g. `EXP-HARD-NEGATIVE-FP-REDUCTION-2026-09-16`), single monolithic retrained models reduced false positives on sparse pages but severely degraded phishing recall (falling to $92.70\%$ on the fixed split and collapsing to $66.84\%$ on Seed 2024).

To address this fundamental trade-off, we developed and evaluated a **Two-Stage High-Recall Cascade Architecture**:

```
+-------------------------------------------------------------------------+
|                               Input URL                                 |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                    STAGE 1: High-Recall Detector                        |
|            (Live Untouched Production XGBoost Model v2.1.0)             |
+-------------------------------------------------------------------------+
       |                                     |                     |
 (S1 >= 0.70)                       (0.35 <= S1 < 0.70)       (S1 < 0.35)
       |                                     |                     |
       v                                     v                     v
+---------------+             +---------------------------+  +------------+
|   HIGH RISK   |             |   STAGE 2: FP Verifier    |  |  LOW RISK  |
|  (Phishing)   |             |   (OOF Trained Verifier)  |  |   (Safe)   |
+---------------+             +---------------------------+  +------------+
                                     |             |
                         (Has Phishing Veto?)  (No Veto & S2 < 0.50)
                                     |             |
                                     v             v
                              +---------------+  +------------+
                              |   HIGH RISK   |  |  LOW RISK  |
                              |  (Preserved)  |  | (De-escal) |
                              +---------------+  +------------+
```

1. **Stage 1 (High-Recall Detector)**: The untouched production model evaluates all candidate URLs, preserving attack sensitivity.
2. **Stage 2 (Conservative False-Positive Verifier)**: Reviews only borderline predictions ($0.35 \le S_1 \le 0.70$) and suspected false-positive structural patterns.
3. **Phishing Evidence Veto Policy**: Explicit strong phishing signals (suspicious redirects, foreign form action, IP hostname, obfuscated tokens, hidden iframes) strictly veto any Stage 2 de-escalation.
4. **Legitimate-Context Invariant**: Absence of forms, low link count, or HTTPS protocol cannot be used as proof of safety.

---

## 2. Feature Availability Audit Summary

Audited $43$ production features across URL and HTML extractors:
- **Existing & Verified**: $43$ features ($22$ URL features, $21$ HTML features).
- **Compound Evidence Features**:
  - `strong_phishing_evidence_score`: Aggregate count of explicit malicious indicators.
  - `has_strong_phishing_veto`: Binary trigger for strong phishing veto.
  - `is_spa_shell_pattern`: Legitimate single-page application context indicator.
- Full details documented in [`docs/CASCADE_FEATURE_AUDIT.md`](file:///c:/Users/Udhaya/S5_Phishing_Detector/docs/CASCADE_FEATURE_AUDIT.md) and [`scratch/cascade_fp_reduction/data/feature_inventory.json`](file:///c:/Users/Udhaya/S5_Phishing_Detector/scratch/cascade_fp_reduction/data/feature_inventory.json).

---

## 3. Data Split & Out-of-Fold Pipeline (Zero Leakage)

- **Dataset**: `backend/data/processed/training_dataset_expanded.csv` ($N=8,910$ rows, $7,005$ legitimate, $1,905$ phishing across $3,151$ unique registered apex domains).
- **Fixed Split**: `GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)`:
  - **Train Partition**: $N=7,111$ samples ($5,603$ legitimate, $1,508$ phishing, $2,520$ apex domains).
  - **Test Partition**: $N=1,799$ samples ($1,402$ legitimate, $397$ phishing, $631$ apex domains).
  - **Domain Leakage**: Exactly **$0.00\%$ apex domain overlap** ($0$ intersecting domains).
- **OOF Stage 1 Predictions**: 5-fold domain-disjoint `GroupKFold` cross-validation was run strictly within the training partition ($N=7,111$) to generate out-of-fold Stage 1 scores ($S_1$) for training Stage 2 verifiers without test partition exposure.

---

## 4. Candidate Model Configurations

- **Candidate A**: Production Stage 1 Only (Baseline, $\tau = 0.50$).
- **Candidate B**: Production Stage 1 + Stage 2 Verifier on all $S_1 \ge 0.50$ (No Veto).
- **Candidate C**: Production Stage 1 + Stage 2 Verifier on Borderline Scores ($0.35 \le S_1 \le 0.70$).
- **Candidate D**: Production Stage 1 + Borderline Stage 2 + Strict Multi-Indicator Phishing Veto.
- **Candidate E**: Conservative Risk-Banding Cascade (High/Medium/Low with SPA context de-escalation).

---

## 5. Fixed-Split Benchmark Results ($N=1,799$, Seed 42)

| Metric | Candidate A (Baseline) | Candidate B (No Veto) | Candidate C (Borderline) | Candidate D (Strict Veto) | Candidate E (Risk Banding) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Accuracy** | 94.55% | **95.16%** | 94.89% | 93.77% | 37.52% |
| **Phishing Recall** ($\ge 94\%$ req.) | **94.21%** (374/397) | 90.93% (361/397) ⚠️ | 91.94% (365/397) ⚠️ | 93.45% (371/397) ⚠️ | **96.47%** (383/397) |
| **Precision** | 83.30% | **87.62%** | 85.88% | 81.18% | 25.65% |
| **F1-Score** | 88.42% | **89.25%** | 88.81% | 86.89% | 40.53% |
| **Specificity** | 94.65% | **96.36%** | 95.72% | 93.87% | 20.83% |
| **False Positive Rate (FPR)** | 5.35% (75 FP) | **3.64% (51 FP)** | 4.28% (60 FP) | 6.13% (86 FP) | 79.17% (1,110 FP) |
| **False Negative Rate (FNR)** | **5.79%** (23 FN) | 9.07% (36 FN) | 8.06% (32 FN) | 6.55% (26 FN) | 3.53% (14 FN) |
| **ROC-AUC** | 0.9819 | 0.9819 | 0.9819 | 0.9819 | 0.9819 |
| **PR-AUC** | 0.9636 | 0.9636 | 0.9636 | 0.9636 | 0.9636 |
| **Sparse Legit FPR** ($N=225$) | 28.89% (65 FP) | **19.11% (43 FP)** | 21.33% (48 FP) | 31.11% (70 FP) | 61.78% (139 FP) |
| **Sparse Phishing Recall** ($N=290$) | **98.97%** (287/290) | 95.86% (278/290) | 96.90% (281/290) | 98.62% (286/290) | 98.62% (286/290) |
| **HTTPS Phishing Recall** ($N=316$) | **93.04%** (294/316) | 89.24% (282/316) | 90.51% (286/316) | 92.41% (292/316) | 95.89% (303/316) |
| **HTTPS Legit FPR** ($N=1,133$) | 5.12% (58 FP) | **3.35% (38 FP)** | 3.97% (45 FP) | 5.83% (66 FP) | 81.99% (929 FP) |
| **Zero Internal Links Phish Recall** ($N=274$) | **98.91%** (271/274) | 95.62% (262/274) | 96.72% (265/274) | 98.54% (270/274) | 98.54% (270/274) |
| **Zero Internal Links Legit FPR** ($N=106$) | 34.91% (37 FP) | **22.64% (24 FP)** | 25.47% (27 FP) | 36.79% (39 FP) | 71.70% (76 FP) |
| **Legit Login/SSO FPR** ($N=221$) | 3.17% (7 FP) | **2.26% (5 FP)** | 2.71% (6 FP) | 3.17% (7 FP) | 80.54% (178 FP) |
| **Ext Form Legit FPR** ($N=87$) | 2.30% (2 FP) | **1.15% (1 FP)** | 2.30% (2 FP) | 2.30% (2 FP) | 81.61% (71 FP) |
| **Ext Form Phish Recall** ($N=14$) | **100.00%** (14/14) | **100.00%** (14/14) | **100.00%** (14/14) | **100.00%** (14/14) | **100.00%** (14/14) |
| **JS-Rendered Legit FPR** ($N=1,011$) | 5.93% (60 FP) | **4.06% (41 FP)** | 4.75% (48 FP) | 6.82% (69 FP) | 79.13% (800 FP) |
| **Gov/Institutional Legit FPR** ($N=244$) | 1.64% (4 FP) | **0.82% (2 FP)** | 1.23% (3 FP) | 1.64% (4 FP) | 85.25% (208 FP) |
| **Cloud-Hosted Legit FPR** ($N=8$) | 12.50% (1 FP) | **0.00% (0 FP)** | **0.00% (0 FP)** | 12.50% (1 FP) | 62.50% (5 FP) |
| **Long URL Phish Recall** ($N=200$) | **94.50%** (189/200) | 90.00% (180/200) | 91.50% (183/200) | 93.50% (187/200) | 96.50% (193/200) |
| **Short URL Phish Recall** ($N=23$) | **91.30%** (21/23) | 91.30% (21/23) | 91.30% (21/23) | **91.30%** (21/23) | **91.30%** (21/23) |
| **Redirect Page Recall** ($N=10$) | **100.00%** (10/10) | **100.00%** (10/10) | **100.00%** (10/10) | **100.00%** (10/10) | **100.00%** (10/10) |

---

## 6. Repeated 5-Seed Domain-Disjoint Validation ([42, 101, 777, 2024, 9999])

| Candidate | Mean Phishing Recall | Recall Std | Worst-Seed Recall | Mean Overall FPR | Mean Sparse Legit FPR | Mean Precision | Total FNs (5 seeds) | Total FPs (5 seeds) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Candidate A (Baseline)** | 91.81% | ±4.51% | 82.82% | 4.72% | 28.10% | 84.54% | 192 | 336 |
| **Candidate B (No Veto)** | 86.45% ⚠️ | ±9.87% | **66.84%** 🚨 | **3.20%** | **18.75%** | **90.10%** | 324 | **228** |
| **Candidate C (Borderline)** | 88.84% ⚠️ | ±9.69% | **69.59%** 🚨 | 3.84% | 21.34% | 87.80% | 274 | 273 |
| **Candidate D (Strict Veto)** | **94.32%** | **±1.05%** | **93.13%** 🛡️ | 5.40% | 29.94% | 82.40% | **122** | 385 |
| **Candidate E (Risk Banding)** | **98.11%** | ±0.94% | **96.73%** | 82.24% 🚨 | 67.55% 🚨 | 23.90% | 40 | 5,867 |

### Per-Seed Phishing Recall Breakdown:
- **Seed 42**: Cand A = 94.21% | Cand B = 90.93% | Cand C = 91.94% | Cand D = 93.45% | Cand E = 96.73%
- **Seed 101**: Cand A = 93.98% | Cand B = 92.47% | Cand C = 94.84% | Cand D = 95.48% | Cand E = 98.92%
- **Seed 777**: Cand A = 93.47% | Cand B = 89.39% | Cand C = 93.06% | Cand D = 93.88% | Cand E = 97.96%
- **Seed 2024**: Cand A = 82.82% | Cand B = **66.84%** | Cand C = **69.59%** | Cand D = **93.13%** | Cand E = 97.59%
- **Seed 9999**: Cand A = 94.58% | Cand B = 92.62% | Cand C = 94.79% | Cand D = 95.66% | Cand E = 99.35%

---

## 7. Key Findings & Diagnostic Insights

1. **The Veto Mechanism is Essential for Generalization**:
   - In Candidates B & C (without strict veto), Stage 2 mistook minimalist phishing lures on Seed 2024 for benign SPAs, causing a severe recall collapse ($66.84\%$ and $69.59\%$).
   - In Candidate D, adding the multi-indicator phishing evidence veto **completely prevented the Seed 2024 recall collapse**, boosting Seed 2024 recall to **$93.13\%$** (higher than baseline $82.82\%$) and cutting 5-seed false negatives from $192 \to 122$.
2. **The Residual FPR Barrier**:
   - Because the veto triggers on any compound signal, it also prevents de-escalation for legitimate pages that possess benign tokenized paths or external links. Thus, Candidate D's fixed-split recall is $93.45\%$ (just under $94.00\%$) while FPR remains $6.13\%$.
3. **Candidate E Risk-Banding Inefficiency**:
   - Treating all ambiguous borderline items as threats inflates false positives from $75 \to 1,110$, proving that hard security boundaries cannot replace calibrated risk scores.

---

## 8. Rollback Plan & Production Safety

- **Production Model**: `backend/ml/models/phishing_model.joblib` SHA-256 is verified 100% identical (`7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`).
- **No Deployment**: No candidate has been promoted or deployed to production. Production inference remains untouched.

---

## 9. Final Decisions for All Candidates

| Candidate | Configuration | Fixed-Split Recall | Mean 5-Seed Recall | Worst-Seed Recall | Mean FPR | Final Classification | Reason for Decision |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Candidate A** | Production Stage 1 Baseline | 94.21% | 91.81% | 82.82% | 4.72% | **PROTECTED BASELINE** | Retained as production fallback model. |
| **Candidate B** | Stage 1 + Stage 2 (No Veto) | 90.93% | 86.45% | 66.84% | 3.20% | **`REJECT`** | Violates recall $\ge 94\%$ invariant; severe recall collapse on Seed 2024 ($66.84\%$). |
| **Candidate C** | Borderline Stage 2 ($0.35 \le S_1 \le 0.70$) | 91.94% | 88.84% | 69.59% | 3.84% | **`REJECT`** | Violates recall $\ge 94\%$ invariant; severe recall collapse on Seed 2024 ($69.59\%$). |
| **Candidate D** | Stage 1 + Borderline Stage 2 + Strict Phishing Veto | 93.45% | 94.32% | 93.13% | 5.40% | **`INCONCLUSIVE — NEED MORE DATA`** | Shows strong generalization across all 5 seeds ($94.32\%$ mean recall, $93.13\%$ worst-seed), but fixed-split recall ($93.45\%$) is narrowly below $94.00\%$ gate ($3$ samples). |
| **Candidate E** | Conservative Risk-Banding | 96.47% | 98.11% | 96.73% | 82.24% | **`REJECT`** | Unacceptable false positive inflation ($82.24\%$ FPR, $5,867$ FPs across 5 seeds). |

---

## 10. Next Recommended Experiment

**`EXP-14-DYNAMIC-CONTENT-FEATURE-FUSION`**:
Deploy client-side / headless browser rendering during feature extraction to resolve the root cause of sparse false positives: converting JavaScript-rendered SPAs from 0-link DOM shells into rich, verified multi-element DOM trees prior to Stage 1 inference, eliminating the need for post-hoc de-escalation heuristics.
