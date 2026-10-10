# Candidate Experiment Report: External Link Concentration (`EXP-EXTERNAL-LINK-CONCENTRATION-2026-09-16`)

**Experiment Identifier:** `EXP-EXTERNAL-LINK-CONCENTRATION-2026-09-16`  
**Candidate Directory:** [`backend/ml/models/candidates_external_link_concentration/`](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/ml/models/candidates_external_link_concentration/)  
**Candidate Model Version:** `2.2.0-candidate-ext-link-concentration`  
**Candidate Model SHA-256:** `9442554d9bb61cdfea074c3feefd44424b141a36b7b0cdd3872284a7d1d748b7`  
**Live Production Model (v2.1.0) SHA-256:** `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` (**VERIFIED 100% UNTOUCHED**)  
**Validation Strategy:** 5-Fold Domain-Disjoint GroupKFold ($0.00\%$ apex domain leakage across $2,441$ train and $608$ test domains)

---

## 1. Executive Summary & Engineering Decision

### 🚨 Final Recommendation: **REJECT CANDIDATE FOR PRODUCTION PROMOTION**

#### Core Decision Rationale:
1. **Critical Attack Recall Failure ($\ge 94.00\%$ Constraint Violated):**
   * At the standard operational threshold ($0.50$), Candidate Model B detected only **$69.78\%$ of phishing attacks** ($291 / 417$, leaving $126$ false negatives), compared to **$98.56\%$ recall** for the live Production Model ($411 / 417$, $6$ false negatives).
   * Even at the most aggressive threshold ($0.30$), Candidate Model B achieved only **$83.93\%$ recall**, remaining far below the required $\ge 94.00\%$ threshold.
2. **Overall Accuracy Below Promotion Criteria ($\ge 95.00\%$):**
   * Candidate Model B achieved **$90.46\%$ accuracy** at threshold $0.50$ (peaking at $91.92\%$ at threshold $0.40$), failing the $\ge 95.00\%$ production requirement.
3. **Severe Regression Across Key Slices:**
   * **HTTPS Phishing Recall:** Plunged from **$98.47\% \implies 67.94\%$** at threshold $0.50$ ($126$ missed secure phishing attacks).
   * **Sparse Phishing Recall ($\le 20$ links):** Plunged from **$98.90\% \implies 68.32\%$** ($115$ missed attacks).
4. **Disproportionate Trade-off on False Positives:**
   * While sparse legitimate page FPR decreased slightly from **$23.78\% \implies 20.00\%$** (a net reduction of $7$ false alarms), it caused an unacceptable loss of **$120$ true positive attack detections**.
5. **Production Model Integrity:**
   * The live production model artifact (`backend/ml/models/phishing_model.joblib`) was verified before and after execution; its SHA-256 hash remains completely identical (`7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`).

---

## 2. Threshold Sweep Comparison: Model A (Production) vs Model B (Candidate)

Evaluation across $N=1,782$ held-out domain-disjoint test samples ($1,365$ legitimate, $417$ phishing):

| Threshold | Model Variant | Accuracy | Phishing Recall | Precision | F1-Score | Specificity | FPR | FNR | ROC-AUC | PR-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **0.30** | **Model A (Production)** | **$95.17\%$** | **$99.76\%$** ($416/417$) | $83.03\%$ | **$90.63\%$** | $93.77\%$ | $6.23\%$ | **$0.24\%$** | **$0.9976$** | **$0.9927$** |
| | **Model B (Candidate)** | $91.47\%$ | $83.93\%$ ($350/417$) | $80.46\%$ | $82.16\%$ | $93.77\%$ | $6.23\%$ | $16.07\%$ | $0.9770$ | $0.9202$ |
| **0.40** | **Model A (Production)** | **$96.35\%$** | **$99.04\%$** ($413/417$) | $87.13\%$ | **$92.70\%$** | $95.53\%$ | $4.47\%$ | **$0.96\%$** | **$0.9976$** | **$0.9927$** |
| | **Model B (Candidate)** | $91.92\%$ | $80.58\%$ ($336/417$) | $84.21\%$ | $82.35\%$ | $95.38\%$ | $4.62\%$ | $19.42\%$ | $0.9770$ | $0.9202$ |
| **0.50** | **Model A (Production)** | **$96.86\%$** | **$98.56\%$** ($411/417$) | **$89.15\%$** | **$93.62\%$** | $96.34\%$ | $3.66\%$ | **$1.44\%$** | **$0.9976$** | **$0.9927$** |
| | **Model B (Candidate)** | $90.46\%$ | $69.78\%$ ($291/417$) | $86.87\%$ | $77.39\%$ | **$96.78\%$** | **$3.22\%$** | $30.22\%$ | $0.9770$ | $0.9202$ |
| **0.60** | **Model A (Production)** | **$97.64\%$** | **$97.84\%$** ($408/417$) | **$92.52\%$** | **$95.10\%$** | $97.58\%$ | $2.42\%$ | **$2.16\%$** | **$0.9976$** | **$0.9927$** |
| | **Model B (Candidate)** | $89.90\%$ | $63.55\%$ ($265/417$) | $90.44\%$ | $74.65\%$ | **$97.95\%$** | **$2.05\%$** | $36.45\%$ | $0.9770$ | $0.9202$ |
| **0.70** | **Model A (Production)** | **$97.76\%$** | **$96.16\%$** ($401/417$) | **$94.35\%$** | **$95.25\%$** | $98.24\%$ | $1.76\%$ | **$3.84\%$** | **$0.9976$** | **$0.9927$** |
| | **Model B (Candidate)** | $88.89\%$ | $57.55\%$ ($240/417$) | $91.95\%$ | $70.80\%$ | **$98.46\%$** | **$1.54\%$** | $42.45\%$ | $0.9770$ | $0.9202$ |

---

## 3. Subclass Slice Analysis Across Thresholds

| Evaluation Slice | Threshold | Model A (Production v2.1.0) | Model B (Candidate B) | Delta / Note |
| :--- | :--- | :--- | :--- | :--- |
| **Sparse Legitimate FPR** ($\le 20$ links, $N=185$) | 0.30 | $35.68\%$ ($66$ FPs) | $33.51\%$ ($62$ FPs) | $-2.17\%$ FPs |
| | 0.40 | $27.57\%$ ($51$ FPs) | $27.03\%$ ($50$ FPs) | $-0.54\%$ FPs |
| | **0.50** | **$23.78\%$** ($44$ FPs) | **$20.00\%$** ($37$ FPs) | **$-3.78\%$ FPs ($-7$ FPs)** |
| | 0.60 | $14.59\%$ ($27$ FPs) | $13.51\%$ ($25$ FPs) | $-1.08\%$ FPs |
| | 0.70 | $10.81\%$ ($20$ FPs) | $10.27\%$ ($19$ FPs) | $-0.54\%$ FPs |
| **Sparse Phishing Recall** ($\le 20$ links, $N=363$) | 0.30 | **$99.72\%$** ($362/363$) | $82.92\%$ ($301/363$) | $-16.80\%$ recall |
| | 0.40 | **$99.17\%$** ($360/363$) | $79.61\%$ ($289/363$) | $-19.56\%$ recall |
| | **0.50** | **$98.90\%$** ($359/363$) | **$68.32\%$** ($248/363$) | **$-30.58\%$ recall ($-111$ detections)** |
| | 0.60 | **$98.07\%$** ($356/363$) | $61.16\%$ ($222/363$) | $-36.91\%$ recall |
| | 0.70 | **$96.97\%$** ($352/363$) | $55.92\%$ ($203/363$) | $-41.05\%$ recall |
| **Shortened URL Phishing Recall** ($N=6$) | 0.30 | **$100.00\%$** ($6/6$) | $83.33\%$ ($5/6$) | $-1$ detection |
| | 0.40 | **$100.00\%$** ($6/6$) | $83.33\%$ ($5/6$) | $-1$ detection |
| | **0.50** | **$83.33\%$** ($5/6$) | **$83.33\%$** ($5/6$) | Equal |
| | 0.60 | **$83.33\%$** ($5/6$) | $66.67\%$ ($4/6$) | $-1$ detection |
| | 0.70 | **$83.33\%$** ($5/6$) | $66.67\%$ ($4/6$) | $-1$ detection |
| **HTTPS Phishing Recall** ($N=393$) | 0.30 | **$99.75\%$** ($392/393$) | $82.95\%$ ($326/393$) | $-16.80\%$ recall |
| | 0.40 | **$98.98\%$** ($389/393$) | $79.39\%$ ($312/393$) | $-19.59\%$ recall |
| | **0.50** | **$98.47\%$** ($387/393$) | **$67.94\%$** ($267/393$) | **$-30.53\%$ recall ($-120$ detections)** |
| | 0.60 | **$97.71\%$** ($384/393$) | $61.32\%$ ($241/393$) | $-36.39\%$ recall |
| | 0.70 | **$95.93\%$** ($377/393$) | $55.22\%$ ($217/393$) | $-40.71\%$ recall |
| **Legitimate Login/SSO Page FPR** ($N=195$) | 0.30 | **$2.56\%$** ($5$ FPs) | $4.10\%$ ($8$ FPs) | $+3$ FPs |
| | 0.40 | **$1.54\%$** ($3$ FPs) | $2.56\%$ ($5$ FPs) | $+2$ FPs |
| | **0.50** | **$1.54\%$** ($3$ FPs) | **$1.54\%$** ($3$ FPs) | Equal |
| | 0.60 | $1.54\%$ ($3$ FPs) | **$1.03\%$** ($2$ FPs) | $-1$ FP |
| | 0.70 | $1.54\%$ ($3$ FPs) | **$0.51\%$** ($1$ FP) | $-2$ FPs |
| **External Form Destination Legitimate FPR** ($N=74$) | **0.50** | **$1.35\%$** ($1$ FP) | **$1.35\%$** ($1$ FP) | Equal |
| **External Form Destination Phish Recall** ($N=24$) | **0.50** | **$100.00\%$** ($24/24$) | $79.17\%$ ($19/24$) | $-5$ detections |

---

## 4. Feature Importance & Concentration Analysis

### Top 15 Tree Gain Features for Candidate Model B:
1. `num_links`: **$0.3007$** ($30.07\%$)
2. `num_internal_links`: **$0.0854$** ($8.54\%$)
3. `domain_length`: **$0.0642$** ($6.42\%$)
4. `num_external_links`: **$0.0389$** ($3.89\%$)
5. **`high_external_link_concentration` (NEW):** **$0.0372$** ($3.72\%$)
6. `uses_https`: **$0.0347$** ($3.47\%$)
7. `external_link_ratio`: **$0.0289$** ($2.89\%$)
8. `num_slashes`: **$0.0265$** ($2.65\%$)
9. `path_length`: **$0.0255$** ($2.55\%$)
10. `num_digits`: **$0.0215$** ($2.15\%$)
11. `path_depth`: **$0.0208$** ($2.08\%$)
12. `num_special_chars`: **$0.0203$** ($2.03\%$)
13. `num_images`: **$0.0192$** ($1.92\%$)
14. `num_scripts`: **$0.0182$** ($1.82\%$)
15. `url_length`: **$0.0179$** ($1.79\%$)

* **Top-2 Feature Concentration:** Dropped from **$43.06\% \implies 38.61\%$** in Candidate Model B.
* `high_external_link_concentration` successfully integrated into the tree splits as the **#5 overall feature** with $3.72\%$ total gain.

---

## 5. Security and Leakage Verification Checklist

- [x] **Zero Domain Leakage:** $0.00\%$ apex domain overlap between $2,441$ training domains and $608$ testing domains.
- [x] **No Static Domain/Provider Allowlists:** Uses solely general structural metrics.
- [x] **All Original Features Preserved:** All 43 baseline production features preserved identically.
- [x] **Live Production Model Untouched:** Production SHA-256 verified identical before and after run: `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2`.
- [x] **Isolated Candidate Artifacts:** All candidate files saved in `backend/ml/models/candidates_external_link_concentration/`.

---

## 6. Reproducibility Command

To reproduce this experiment and verify all empirical numbers:

```powershell
backend\venv\Scripts\python.exe backend\ml\training\train_candidate_external_link_concentration.py
```

### Artifact Paths:
* Candidate Model: `backend/ml/models/candidates_external_link_concentration/candidate_external_link_model.joblib`
* Candidate Feature Columns: `backend/ml/models/candidates_external_link_concentration/candidate_feature_columns.json`
* Candidate Metadata: `backend/ml/models/candidates_external_link_concentration/candidate_metadata.json`
* Full JSON Report: `backend/ml/models/candidates_external_link_concentration/candidate_experiment_report.json`
* Feature Importances: `backend/ml/models/candidates_external_link_concentration/candidate_feature_importances.json`
