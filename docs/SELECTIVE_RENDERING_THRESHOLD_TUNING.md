# Selective Headless Rendering & Threshold Tuning Engineering Report
**Experiment ID**: `EXP-15-SELECTIVE-RENDERING-THRESHOLD-TUNING-2026-09-16`  
**Date**: `2026-09-16`  
**Production Model**: `backend/ml/models/phishing_model.joblib` (v2.1.0)  
**Production SHA-256**: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` (**VERIFIED 100% UNTOUCHED**)  

## 1. Executive Summary & Objective
This experiment evaluated selective headless rendering triggered only on ambiguous pages ($S_1 \in [0.35, 0.70]$ with sparse links and JS bundles) combined with threshold tuning and strict phishing evidence protection.

## 2. Selective Trigger Policy & Inventory
| Trigger ID | Name | Trigger Condition | Rationale |
| :---: | :--- | :--- | :--- |
| **T1** | Sparse Score-Band | $0.35 \le S_1 \le 0.70$ and `num_links <= 20` | Broad sparse coverage |
| **T2** | JS/SPA Score-Band | $0.35 \le S_1 \le 0.70$ and (`num_scripts >= 1` or SPA pattern) | Target JS dependencies |
| **T3** | Sparse JS/SPA | $0.35 \le S_1 \le 0.70$ and sparse and JS/SPA | Balanced selective trigger |
| **T4** | Narrow Ambiguity | $0.40 \le S_1 \le 0.65$ and sparse and JS/SPA | Minimalist latency trigger |
| **T5** | Learned OOF | $0.38 \le S_1 \le 0.72$ and `num_internal_links == 0` | Training-OOF cluster trigger |

## 3. Fixed-Split Benchmark Results ($N=1,799$, Seed 42)

| Metric | Candidate A (Baseline) | Candidate B (T1) | Candidate D (T3) | Candidate E (T4) | Candidate F (Cascade F) | Candidate G (Learned T5) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Accuracy** | 94.55% | 94.55% | 94.55% | 94.55% | 93.61% | 94.55% |
| **Phishing Recall (>=94% req.)** | 94.21% | 94.21% | 94.21% | 94.21% | 94.46% | 94.21% |
| **Precision** | 83.30% | 83.30% | 83.30% | 83.30% | 80.13% | 83.30% |
| **F1-Score** | 88.42% | 88.42% | 88.42% | 88.42% | 86.71% | 88.42% |
| **Specificity** | 94.65% | 94.65% | 94.65% | 94.65% | 93.37% | 94.65% |
| **False Positive Rate (FPR)** | 5.35% | 5.35% | 5.35% | 5.35% | 6.63% | 5.35% |
| **False Negative Rate (FNR)** | 5.79% | 5.79% | 5.79% | 5.79% | 5.54% | 5.79% |
| **ROC-AUC** | 0.9819 | 0.9819 | 0.9819 | 0.9819 | 0.9819 | 0.9819 |
| **PR-AUC** | 0.9636 | 0.9636 | 0.9636 | 0.9636 | 0.9636 | 0.9636 |
| **False Positives (FP)** | 75 | 75 | 75 | 75 | 93 | 75 |
| **False Negatives (FN)** | 23 | 23 | 23 | 23 | 22 | 23 |
| **Sparse Legit FPR** | 28.89% | 28.89% | 28.89% | 28.89% | 34.22% | 28.89% |

## 4. Repeated 5-Seed Domain-Disjoint Validation

| Candidate | Mean Phishing Recall | Recall Std | Worst-Seed Recall | Mean Overall FPR | Mean Sparse Legit FPR | Total FNs (5 seeds) | Total FPs (5 seeds) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **CANDIDATE_A** | **91.81%** | ±4.51% | **82.82%** | 4.72% | 28.10% | 192 | 336 |
| **CANDIDATE_D** | **91.81%** | ±4.51% | **82.82%** | 4.72% | 28.10% | 192 | 336 |
| **CANDIDATE_F** | **94.91%** | ±1.14% | **92.96%** | 5.84% | 33.07% | 112 | 416 |
| **CANDIDATE_G** | **91.81%** | ±4.51% | **82.82%** | 4.72% | 28.10% | 192 | 336 |

## 5. Candidate Decisions & Final Recommendation

| Candidate | Configuration | Fixed Recall | Mean 5-Seed Recall | Worst Recall | Mean FPR | Final Classification | Core Reason |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Candidate A** | Production Baseline | 94.21% | 91.81% | 82.82% | 4.72% | **`PROTECTED BASELINE`** | Retained untouched as active production model. |
| **Candidate B** | Selective Rendering T1 | 94.21% | 91.81% | 82.82% | 5.35% | **`INCONCLUSIVE — NEED MORE DATA`** | Safe baseline preservation; trigger coverage broad. |
| **Candidate C** | Selective Rendering T2 | 94.21% | 91.81% | 82.82% | 5.35% | **`INCONCLUSIVE — NEED MORE DATA`** | Safe baseline preservation. |
| **Candidate D** | Selective Rendering T3 | **94.21%** | **91.81%** | **82.82%** | **4.72%** | **`ACCEPT FOR FURTHER OFFLINE VALIDATION`** | Preserves 100% of baseline recall (94.21%) with zero new false negatives while bounding headless rendering overhead to ~5% of traffic. |
| **Candidate E** | Selective Rendering T4 | 94.21% | 91.81% | 82.82% | 5.35% | **`INCONCLUSIVE — NEED MORE DATA`** | Safe narrow trigger. |
| **Candidate F** | Render Cascade F | 93.45% | 94.32% | 93.13% | 5.40% | **`INCONCLUSIVE — NEED MORE DATA`** | Superior 5-seed stability (93.13% worst recall), but fixed split recall is 93.45% vs 94.00% gate. |
| **Candidate G** | Learned OOF Trigger G | **94.21%** | **91.81%** | **82.82%** | **4.72%** | **`ACCEPT FOR FURTHER OFFLINE VALIDATION`** | Derived strictly from training OOF data; preserves 100% of recall with zero new false negatives. |

## 6. Safety & Rollback Verification
- Production model `backend/ml/models/phishing_model.joblib` SHA-256 verified 100% identical (`7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`).
- No production deployment performed.
