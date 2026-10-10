# Semantic & Behavioral Candidate: Repeated Multi-Seed Validation Report

**Experiment Title:** Semantic Candidate Multi-Seed Repeated Domain-Grouped Validation  
**Date:** `2026-09-16`  
**Dataset:** [`backend/data/processed/training_dataset_expanded.csv`](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/data/processed/training_dataset_expanded.csv) ($8,910$ total rows)  
**Partition Strategy:** `GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed)` across $5$ diverse random seeds: `[42, 101, 777, 2024, 9999]`  
**Live Production Model (v2.1.0) SHA-256:** `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` (**VERIFIED 100% UNTOUCHED**)  
**JSON Results:** [`scratch/semantic_candidate_repeated_validation.json`](file:///c:/Users/Udhaya/S5_Phishing_Detector/scratch/semantic_candidate_repeated_validation.json)  
**Runner Script:** [`scratch/run_semantic_candidate_repeated_validation.py`](file:///c:/Users/Udhaya/S5_Phishing_Detector/scratch/run_semantic_candidate_repeated_validation.py)

---

## 1. Executive Summary & Recommendation

### ⚖️ Final Recommendation: **INCONCLUSIVE — NEED MORE DATA**

#### Key Decision Rationale:
1. **Precision & False Positive Reduction is Robust:**
   * Across all 5 evaluation seeds, the Semantic Candidate (54 features) **consistently improved precision** ($+0.78\%$ average boost across all seeds: $85.33\%$ vs $84.54\%$) and reduced overall false alarms (average FPR decreased from $4.72\% \implies 4.40\%$, eliminating an average of $4.6$ false positives per test fold).
2. **Shortened URL and Login Coverage Improved:**
   * Shortened URL phishing recall improved from **$93.43\% \implies 94.55\%$** across seeds.
   * Legitimate login/SSO false positive rate improved from **$3.14\% \implies 2.80\%$**.
3. **Seed Variance in Attack Recall:**
   * On 3 out of 5 seeds (Seeds 42, 101, 777), semantic features maintained or improved attack recall ($\Delta \in [0.00\%, +0.41\%]$).
   * However, on Seed 2024 (a difficult out-of-domain cluster), both models experienced domain shift, with the semantic candidate suffering a $-6.19\%$ recall drop at the rigid $0.50$ threshold.
   * Across the 5 seeds, mean phishing recall was **$90.57\% \pm 6.97\%$** for the Semantic Candidate vs **$91.81\% \pm 4.51\%$** for the Baseline.
4. **Conservative Engineering Conclusion:**
   * While the semantic features introduce real discriminative value (reducing false positives and improving precision), a rigid $0.50$ decision threshold on uncalibrated tree logits causes seed-dependent recall instability. 
   * The candidate cannot be promoted directly without further threshold calibration and out-of-domain data expansion.

---

## 2. Split-by-Split Performance Breakdown (Identical Held-Out Rows)

All models evaluated within each seed on the exact same held-out test rows ($0.00\%$ domain overlap):

| Seed | Model Architecture | Test Rows ($N$) | Phishing / Legit | Accuracy | Recall | Precision | F1-Score | Specificity | FPR | FN Count | FP Count |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **42** | **Baseline (43 Feats)** | $1,799$ | $397$ / $1,402$ | $94.55\%$ | **$94.21\%$** | $83.30\%$ | $88.42\%$ | $94.65\%$ | $5.35\%$ | $23$ | $75$ |
| | **Semantic (54 Feats)** | $1,799$ | $397$ / $1,402$ | **$94.66\%$** | **$94.21\%$** | **$83.67\%$** | **$88.63\%$** | **$94.79\%$** | **$5.21\%$** | $23$ ($0$) | **$73$** ($-2$) |
| **101** | **Baseline (43 Feats)** | $1,779$ | $465$ / $1,314$ | $94.33\%$ | $93.98\%$ | $84.69\%$ | $89.09\%$ | $94.44\%$ | $5.56\%$ | $28$ | $79$ |
| | **Semantic (54 Feats)** | $1,779$ | $465$ / $1,314$ | **$94.59\%$** | **$94.19\%$** | **$85.38\%$** | **$89.57\%$** | **$94.73\%$** | **$5.27\%$** | **$27$** ($-1$) | **$75$** ($-4$) |
| **777** | **Baseline (43 Feats)** | $1,780$ | $245$ / $1,535$ | $94.70\%$ | $93.47\%$ | $75.83\%$ | $83.73\%$ | $94.91\%$ | $5.09\%$ | $16$ | $73$ |
| | **Semantic (54 Feats)** | $1,780$ | $245$ / $1,535$ | **$95.23\%$** | **$93.88\%$** | **$77.97\%$** | **$85.19\%$** | **$95.46\%$** | **$4.54\%$** | **$15$** ($-1$) | **$65$** ($-8$) |
| **2024** | **Baseline (43 Feats)** | $1,811$ | $582$ / $1,229$ | **$91.85\%$** | **$82.82\%$** | $88.44\%$ | **$85.54\%$** | $95.56\%$ | $4.44\%$ | $100$ | $63$ |
| | **Semantic (54 Feats)** | $1,811$ | $582$ / $1,229$ | $90.40\%$ | $76.63\%$ | **$88.84\%$** | $82.29\%$ | **$96.05\%$** | **$3.95\%$** | $136$ ($+36$) | **$56$** ($-7$) |
| **9999** | **Baseline (43 Feats)** | $1,768$ | $461$ / $1,307$ | **$96.30\%$** | **$94.58\%$** | $90.46\%$ | **$92.47\%$** | $96.84\%$ | $3.16\%$ | $25$ | $46$ |
| | **Semantic (54 Feats)** | $1,768$ | $461$ / $1,307$ | $96.24\%$ | $93.93\%$ | **$90.78\%$** | $92.32\%$ | **$96.98\%$** | **$3.02\%$** | $28$ ($+3$) | **$44$** ($-2$) |

---

## 3. Aggregate Statistical Summary Across 5 Random Seeds

Metrics reported as **Mean $\pm$ Standard Deviation** ($[\text{Min}, \text{Max}]$):

| Metric | Retrained Baseline (43 Feats) | Semantic Candidate (54 Feats) | Delta (Semantic vs Baseline) | Consistency Check |
| :--- | :--- | :--- | :--- | :--- |
| **Phishing Recall** | **$91.81\% \pm 4.51\%$** [$82.82\%, 94.58\%$] | $90.57\% \pm 6.97\%$ [$76.63\%, 94.21\%$] | $-1.24\%$ | Wins: 2, Ties: 1, Losses: 2 |
| **Overall Accuracy** | **$94.35\% \pm 1.43\%$** [$91.85\%, 96.30\%$] | $94.22\% \pm 2.00\%$ [$90.40\%, 96.24\%$] | $-0.13\%$ | Wins: 3, Ties: 0, Losses: 2 |
| **Precision** | $84.54\% \pm 5.05\%$ [$75.83\%, 90.46\%$] | **$85.33\% \pm 4.45\%$** [$77.97\%, 90.78\%$] | **$+0.79\%$** | **Wins: 5, Ties: 0, Losses: 0** |
| **F1-Score** | **$87.85\% \pm 3.02\%$** [$83.73\%, 92.47\%$] | $87.60\% \pm 3.50\%$ [$82.29\%, 92.32\%$] | $-0.25\%$ | Wins: 3, Ties: 0, Losses: 2 |
| **Specificity** | $95.28\% \pm 0.87\%$ [$94.44\%, 96.84\%$] | **$95.60\% \pm 0.84\%$** [$94.73\%, 96.98\%$] | **$+0.32\%$** | **Wins: 5, Ties: 0, Losses: 0** |
| **False Positive Rate (FPR)** | $4.72\% \pm 0.87\%$ [$3.16\%, 5.56\%$] | **$4.40\% \pm 0.84\%$** [$3.02\%, 5.27\%$] | **$-0.32\%$** | **Wins: 5, Ties: 0, Losses: 0** |
| **Mean False Negative Count** | **$38.4$ FNs** | $45.8$ FNs | $+7.4$ FNs | Seed 2024 drove outlier |
| **Mean False Positive Count** | $67.2$ FPs | **$62.6$ FPs** | **$-4.6$ FPs** | **Consistent reduction across all seeds** |
| **ROC-AUC** | **$0.9846 \pm 0.0053$** | $0.9843 \pm 0.0054$ | $-0.0003$ | Parity |
| **PR-AUC** | $0.9599 \pm 0.0143$ | **$0.9604 \pm 0.0144$** | **$+0.0005$** | Parity |

---

## 4. Aggregate Subclass Slice Comparison Across Seeds

| Evaluation Slice | Retrained Baseline (43 Feats) | Semantic Candidate (54 Feats) | Empirical Observation |
| :--- | :--- | :--- | :--- |
| **Sparse Legitimate Pages FPR ($\le 20$ links)** | $28.10\% \pm 4.12\%$ | **$27.51\% \pm 4.03\%$** | **$-0.59\%$ FPR improvement** |
| **Sparse Phishing Recall ($\le 20$ links)** | **$95.50\% \pm 5.54\%$** | $93.86\% \pm 8.64\%$ | $-1.64\%$ mean recall |
| **HTTPS Phishing Recall** | **$90.75\% \pm 5.31\%$** | $89.46\% \pm 8.23\%$ | $-1.29\%$ mean recall |
| **Shortened URL Phishing Recall** | $93.43\% \pm 10.57\%$ | **$94.55\% \pm 10.91\%$** | **$+1.12\%$ recall improvement** |
| **Legitimate Login/SSO FPR** | $3.14\% \pm 0.79\%$ | **$2.80\% \pm 0.83\%$** | **$-0.34\%$ FPR improvement** |
| **External Form Action Pages (Legit FPR)** | $0.96\% \pm 0.88\%$ | $0.96\% \pm 0.88\%$ | Identical ($0$ regression) |
| **External Form Action Pages (Phish Recall)** | $97.84\% \pm 4.32\%$ | $97.84\% \pm 4.32\%$ | Identical ($0$ regression) |

---

## 5. Security and Leakage Audit Verification

- [x] **Zero Domain Overlap on All Seeds:** $0.00\%$ domain leakage across every random seed partition ($[42, 101, 777, 2024, 9999]$).
- [x] **Production Model Untouched:** SHA-256 verified identical before and after: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`.
- [x] **No Static Domain/Provider Allowlists Used.**
- [x] **Score Calibration Safety:** All scores documented strictly as uncalibrated monotonic tree threat indicators.
- [x] **No Automatic Deployment:** Live production model v2.1.0 remains active and unchanged.
