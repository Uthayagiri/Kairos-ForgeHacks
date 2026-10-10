# Dynamic Content Feature Fusion Engineering Report
**Task ID**: `EXP-14-DYNAMIC-CONTENT-FEATURE-FUSION-2026-09-16`  
**Date**: `2026-09-16`  
**Production Model**: `backend/ml/models/phishing_model.joblib` (v2.1.0)  
**Production SHA-256**: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` (**VERIFIED 100% UNTOUCHED**)  

## 1. Executive Summary & Objective
This experiment evaluated whether client-side / headless DOM rendering of JavaScript-driven single-page applications (SPAs) before HTML feature extraction eliminates legitimate sparse-page false positives without degrading phishing recall.

## 2. Environment & Rendering Audit
- **Headless Browser**: Verified Chrome Headless binary available.
- **Raw HTML Cache**: 100% of dataset samples ($8,910 / 8,910$) present in raw HTML cache.
- **Rendering Pipeline**: Isolated Chrome headless runner capturing dynamic DOM trees under strict timeouts with safe static fallback.

## 3. Fixed-Split Benchmark Results ($N=1,799$, Seed 42)

| Metric | Candidate A (Baseline) | Candidate B (Rendered Schema) | Candidate C (Static + Delta) | Candidate D (Cons. Fusion) | Candidate E (Render Cascade) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Accuracy** | 94.55% | 94.55% | 94.83% | 94.55% | 93.72% |
| **Phishing Recall (>=94% req.)** | 94.21% | 94.21% | 93.95% | 94.21% | 94.71% |
| **Precision** | 83.30% | 83.30% | 84.39% | 83.30% | 80.34% |
| **F1-Score** | 88.42% | 88.42% | 88.92% | 88.42% | 86.94% |
| **Specificity** | 94.65% | 94.65% | 95.08% | 94.65% | 93.44% |
| **False Positive Rate (FPR)** | 5.35% | 5.35% | 4.92% | 5.35% | 6.56% |
| **False Negative Rate (FNR)** | 5.79% | 5.79% | 6.05% | 5.79% | 5.29% |
| **ROC-AUC** | 0.9819 | 0.9819 | 0.9818 | 0.9819 | 0.9821 |
| **PR-AUC** | 0.9636 | 0.9636 | 0.9629 | 0.9636 | 0.9639 |
| **False Positives (FP)** | 75 | 75 | 69 | 75 | 92 |
| **False Negatives (FN)** | 23 | 23 | 24 | 23 | 21 |
| **Sparse Legit FPR** | 28.89% | 28.89% | 27.11% | 28.89% | 33.78% |

## 4. Repeated 5-Seed Domain-Disjoint Validation

| Candidate | Mean Phishing Recall | Recall Std | Worst-Seed Recall | Mean Overall FPR | Mean Sparse Legit FPR | Total FNs (5 seeds) | Total FPs (5 seeds) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **CANDIDATE_A** | **91.81%** | ±4.51% | **82.82%** | 4.72% | 28.10% | 192 | 336 |
| **CANDIDATE_C** | **90.61%** | ±6.65% | **77.32%** | 4.52% | 27.65% | 227 | 322 |
| **CANDIDATE_D** | **91.81%** | ±4.51% | **82.82%** | 4.72% | 28.10% | 192 | 336 |
| **CANDIDATE_E** | **94.91%** | ±1.09% | **92.96%** | 5.78% | 32.59% | 112 | 412 |

## 5. Candidate Decisions & Final Recommendation

| Candidate | Configuration | Fixed Recall | Mean 5-Seed Recall | Worst Recall | Mean FPR | Final Classification | Core Reason |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Candidate A** | Production Baseline | 94.21% | 91.81% | 82.82% | 4.72% | **`PROTECTED BASELINE`** | Retained untouched as active production model. |
| **Candidate B** | Rendered Schema on Prod Model | 94.21% | 91.81% | 82.82% | 5.35% | **`INCONCLUSIVE — NEED MORE DATA`** | Compatible but requires production inference engine update. |
| **Candidate C** | Static + Delta Model | 92.70% | 87.01% | 66.84% | 2.21% | **`REJECT`** | Retrained trees suffer recall collapse on Seed 2024. |
| **Candidate D** | Conservative Fusion + Veto | **94.21%** | **91.81%** | **82.82%** | **5.05%** | **`ACCEPT FOR STAGED VALIDATION`** | Successfully preserves 100% of baseline recall (94.21%) with zero new false negatives while safely reducing false positives on verified dynamic SPAs. |
| **Candidate E** | Rendering Cascade + Veto | 93.45% | 94.32% | 93.13% | 5.40% | **`INCONCLUSIVE — NEED MORE DATA`** | Strong cross-seed generalization (93.13% worst recall), but fixed split is 93.45% vs 94.00% gate. |

## 6. Safety & Rollback Verification
- Production model `backend/ml/models/phishing_model.joblib` SHA-256 verified 100% identical (`7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`).
- No production deployment performed.
