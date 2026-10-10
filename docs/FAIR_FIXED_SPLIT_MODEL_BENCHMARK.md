# Fair Fixed-Split Model Benchmark Across All Candidates

**Benchmark Date:** `2026-09-16`  
**Evaluation Split Strategy:** `GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)`  
**Dataset:** [`backend/data/processed/training_dataset_expanded.csv`](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/data/processed/training_dataset_expanded.csv) ($8,910$ total samples)  
**Partition Sizes:**
* **Training Partition:** $7,111$ samples ($5,603$ legitimate, $1,508$ phishing, $2,520$ registered apex domains)
* **Held-Out Test Partition:** $1,799$ samples ($1,402$ legitimate, $397$ phishing, $631$ registered apex domains)
* **Domain Leakage Audit:** **$0.00\%$** ($0$ overlapping domains between train and test)
**Live Production Model (v2.1.0) SHA-256:** `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` (**VERIFIED 100% UNTOUCHED**)  
**Benchmark JSON Data:** [`scratch/fair_fixed_split_benchmark.json`](file:///c:/Users/Udhaya/S5_Phishing_Detector/scratch/fair_fixed_split_benchmark.json)  
**Benchmark Runner:** [`scratch/run_fair_fixed_split_benchmark.py`](file:///c:/Users/Udhaya/S5_Phishing_Detector/scratch/run_fair_fixed_split_benchmark.py)

---

## 1. Executive Summary & Context

### Background
Earlier candidate experiments produced misleading results because the pre-trained Production Model v2.1.0 was evaluated on a `GroupKFold` partition where **$91.58\%$ ($370 / 404$)** of the phishing test samples were part of its original training set (in-sample contamination). 

To eliminate all evaluation bias, this benchmark evaluates the **Live Production Model** and all **4 Candidate Architectures** on the **EXACT SAME** held-out test rows ($N=1,799$ samples from $631$ unseen domains) under standard decision threshold $0.50$.

---

## 2. Core Metrics Comparison on Identical Held-Out Rows ($N=1,799$)

| Metric | Model 1: Live Production (v2.1.0) | Model 2: Retrained 43-Feat Baseline | Model 3: Link-Density Candidate | Model 4: Semantic/Behavior Candidate | Model 5: External-Link Candidate | Target / Constraint |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Feature Count** | 43 | 43 | 47 | **54** | 44 | — |
| **Accuracy** | **$94.55\%$** | **$94.55\%$** | **$94.83\%$** | **$94.66\%$** | **$94.50\%$** | $\ge 95.00\%$ |
| **Phishing Recall** | **$94.21\%$** ($374/397$) | **$94.21\%$** ($374/397$) | $93.45\%$ ($371/397$) | **$94.21\%$** ($374/397$) | $93.95\%$ ($373/397$) | **$\ge 94.00\%$** |
| **Precision** | $83.30\%$ | $83.30\%$ | **$84.70\%$** | **$83.67\%$** | $83.26\%$ | $\ge 85.00\%$ |
| **F1-Score** | $88.42\%$ | $88.42\%$ | **$88.86\%$** | **$88.63\%$** | $88.28\%$ | — |
| **Specificity** | $94.65\%$ | $94.65\%$ | **$95.22\%$** | **$94.79\%$** | $94.65\%$ | — |
| **FPR** | $5.35\%$ ($75/1402$) | $5.35\%$ ($75/1402$) | **$4.78\%$** ($67/1402$) | **$5.21\%$** ($73/1402$) | $5.35\%$ ($75/1402$) | — |
| **FNR** | $5.79\%$ ($23/397$) | $5.79\%$ ($23/397$) | $6.55\%$ ($26/397$) | **$5.79\%$** ($23/397$) | $6.05\%$ ($24/397$) | — |
| **ROC-AUC** | $0.9819$ | $0.9819$ | **$0.9847$** | **$0.9821$** | $0.9818$ | — |
| **PR-AUC** | $0.9636$ | $0.9636$ | **$0.9674$** | **$0.9654$** | $0.9623$ | — |
| **Brier Score** | $0.0390$ | $0.0390$ | **$0.0367$** | **$0.0383$** | $0.0396$ | — |
| **Meets Recall Target?** | **YES ($94.21\%$)** | **YES ($94.21\%$)** | ❌ NO ($93.45\%$) | **YES ($94.21\%$)** | ❌ NO ($93.95\%$) | $\ge 94.00\%$ |

---

## 3. Subclass Slice Performance on Held-Out Test Set

| Subclass Slice | Sample Size ($N$) | Model 1 (Prod v2.1.0) | Model 2 (Retrained) | Model 3 (Link-Density) | Model 4 (Semantic/Behavior) | Model 5 (External-Link) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Sparse Legitimate Pages ($\le 20$ links)** | $N=225$ | $28.89\%$ ($65$ FPs) | $28.89\%$ ($65$ FPs) | **$27.11\%$** ($61$ FPs) | $29.78\%$ ($67$ FPs) | $29.33\%$ ($66$ FPs) |
| **Sparse Phishing Pages ($\le 20$ links)** | $N=290$ | **$98.97\%$** ($287/290$) | **$98.97\%$** ($287/290$) | **$98.97\%$** ($287/290$) | $98.62\%$ ($286/290$) | $98.62\%$ ($286/290$) |
| **HTTPS Phishing Recall** | $N=316$ | **$93.04\%$** ($294/316$) | **$93.04\%$** ($294/316$) | $92.09\%$ ($291/316$) | **$93.04\%$** ($294/316$) | $92.72\%$ ($293/316$) |
| **Shortened URL Phishing Recall** | $N=18$ | $94.44\%$ ($17/18$) | $94.44\%$ ($17/18$) | $83.33\%$ ($15/18$) | **$100.00\%$** ($18/18$) | $94.44\%$ ($17/18$) |
| **Legitimate Login/SSO FPR** | $N=221$ | **$3.17\%$** ($7$ FPs) | **$3.17\%$** ($7$ FPs) | $4.07\%$ ($9$ FPs) | $3.62\%$ ($8$ FPs) | $3.62\%$ ($8$ FPs) |
| **External Form Action Pages (Legit FPR)** | $N=87$ | **$2.30\%$** ($2/87$) | **$2.30\%$** ($2/87$) | **$2.30\%$** ($2/87$) | **$2.30\%$** ($2/87$) | **$2.30\%$** ($2/87$) |
| **External Form Action Pages (Phish Recall)** | $N=14$ | **$100.00\%$** ($14/14$) | **$100.00\%$** ($14/14$) | **$100.00\%$** ($14/14$) | **$100.00\%$** ($14/14$) | **$100.00\%$** ($14/14$) |

---

## 4. Confusion Matrices Breakdown

* **Model 1 (Live Production v2.1.0):** $\text{TN}=1327, \text{FP}=75, \text{FN}=23, \text{TP}=374$
* **Model 2 (Retrained 43-Feat Baseline):** $\text{TN}=1327, \text{FP}=75, \text{FN}=23, \text{TP}=374$ (Identical replication)
* **Model 3 (Link-Density Candidate):** $\text{TN}=1335, \text{FP}=67, \text{FN}=26, \text{TP}=371$ ($8$ fewer false alarms, but $3$ more missed attacks)
* **Model 4 (Semantic/Behavior Candidate):** $\text{TN}=1329, \text{FP}=73, \text{FN}=23, \text{TP}=374$ ($2$ fewer false alarms, zero additional missed attacks, perfect short-URL detection)
* **Model 5 (External-Link-Concentration Candidate):** $\text{TN}=1327, \text{FP}=75, \text{FN}=24, \text{TP}=373$ ($1$ additional missed attack)

---

## 5. Output Probability Distributions (Raw XGBoost Scores)

> [!NOTE]
> These raw scores are uncalibrated sigmoid tree outputs from models trained with `scale_pos_weight = 5.0`. They represent monotonic ranking scores, not empirical posterior probabilities.

### Phishing Attack Samples ($N=397$):
* **Model 1 (Production):** Mean $= 0.8977$, Median $= 0.9805$, Std $= 0.2155$, $\text{P10}=0.6772$, $\text{P25}=0.9298$, $\text{P75}=0.9980$, $\text{P90}=0.9996$
* **Model 2 (Retrained):** Mean $= 0.8977$, Median $= 0.9805$, Std $= 0.2155$, $\text{P10}=0.6772$, $\text{P25}=0.9298$, $\text{P75}=0.9980$, $\text{P90}=0.9996$
* **Model 3 (Link-Density):** Mean $= 0.8969$, Median $= 0.9825$, Std $= 0.2189$, $\text{P10}=0.6853$, $\text{P25}=0.9182$, $\text{P75}=0.9980$, $\text{P90}=0.9995$
* **Model 4 (Semantic/Behavior):** Mean $= 0.8976$, Median $= 0.9821$, Std $= 0.2151$, $\text{P10}=0.7022$, $\text{P25}=0.9293$, $\text{P75}=0.9979$, $\text{P90}=0.9995$
* **Model 5 (External-Link):** Mean $= 0.8942$, Median $= 0.9821$, Std $= 0.2167$, $\text{P10}=0.6767$, $\text{P25}=0.9010$, $\text{P75}=0.9980$, $\text{P90}=0.9995$

### Legitimate Page Samples ($N=1,402$):
* **Model 1 (Production):** Mean $= 0.0715$, Median $= 0.0079$, Std $= 0.1699$, $\text{P90}=0.2132$, $\text{P95}=0.5098$, $\text{P99}=0.8376$
* **Model 2 (Retrained):** Mean $= 0.0715$, Median $= 0.0079$, Std $= 0.1699$, $\text{P90}=0.2132$, $\text{P95}=0.5098$, $\text{P99}=0.8376$
* **Model 3 (Link-Density):** Mean $= 0.0681$, Median $= 0.0094$, Std $= 0.1608$, $\text{P90}=0.1974$, $\text{P95}=0.4889$, $\text{P99}=0.7787$
* **Model 4 (Semantic/Behavior):** Mean $= 0.0704$, Median $= 0.0089$, Std $= 0.1675$, $\text{P90}=0.1894$, $\text{P95}=0.5225$, $\text{P99}=0.8043$
* **Model 5 (External-Link):** Mean $= 0.0718$, Median $= 0.0084$, Std $= 0.1709$, $\text{P90}=0.2138$, $\text{P95}=0.5198$, $\text{P99}=0.8263$

---

## 6. Neutral Candidate Evaluation & Threshold Assessment

### Which Candidates Meet the Mandatory $\ge 94.00\%$ Recall Threshold?

1. **Model 4 (Semantic & Behavioral Candidate, 54 Features):**
   * **Recall:** **$94.21\%$** ($374 / 397$) $\implies$ **MEETS THRESHOLD ($\ge 94.00\%$)**
   * **Accuracy:** **$94.66\%$** (highest among all models preserving recall)
   * **Precision:** **$83.67\%$** ($+0.37\%$ improvement over production)
   * **F1-Score:** **$88.63\%$** ($+0.21\%$ improvement over production)
   * **Shortened URL Recall:** **$100.00\%$** ($18/18$ vs $17/18$ in production)
   * **Assessment:** Best-performing candidate overall; matches production recall while slightly improving precision, ROC-AUC ($0.9821$), and shortened URL detection.

2. **Model 1 (Live Production Model v2.1.0):**
   * **Recall:** **$94.21\%$** ($374 / 397$) $\implies$ **MEETS THRESHOLD ($\ge 94.00\%$)**
   * Remains the active production benchmark.

3. **Model 3 (Link-Density Normalization Candidate, 47 Features):**
   * **Recall:** **$93.45\%$** ($371 / 397$) $\implies$ **FAILS THRESHOLD ($< 94.00\%$)**
   * While it achieved highest specificity ($95.22\%$) and lowest FPR ($4.78\%$), dropping `num_internal_links` causes a drop in attack recall below $94.00\%$ and degraded shortened URL recall ($83.33\%$).

4. **Model 5 (External-Link-Concentration Candidate, 44 Features):**
   * **Recall:** **$93.95\%$** ($373 / 397$) $\implies$ **FAILS THRESHOLD ($< 94.00\%$)**
   * Misses $1$ additional attack compared to baseline, failing the strict $94.00\%$ floor by $0.05\%$.

---

## 7. Safety & Integrity Verifications

- [x] **Identical Held-Out Test Set:** All 5 models evaluated on the exact same $1,799$ rows.
- [x] **Zero Domain Leakage:** $0.00\%$ apex domain overlap between train and test.
- [x] **Zero Production Modification:** SHA-256 verified identical: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`.
- [x] **No Static Allowlisting:** Evaluation is strictly general and algorithmic.
- [x] **No Automatic Deployment:** All models remain isolated.
