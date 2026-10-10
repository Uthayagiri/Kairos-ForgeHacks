# Candidate Experiment Report: Link-Density Feature Normalization & Shortcut Reduction

**Experiment Identifier:** `EXP-LINK-DENSITY-2026-09-16`  
**Candidate Directory:** `backend/ml/models/candidates_link_density/`  
**Candidate Model Version:** `2.2.0-candidate-link-density`  
**Candidate Model SHA-256:** `e3aacd38aa335aa38befa2844d9e71a466fc6aadf226a4fa625d6984a4c51827`  
**Validation Strategy:** 5-Fold Domain-Disjoint GroupKFold ($0.00\%$ apex domain leakage)  
**Live Production Model (v2.1.0) SHA-256:** `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` (**VERIFIED UNTOUCHED**)  

---

## 1. Executive Summary & Promotion Recommendation

### 🚨 Promotion Recommendation: **REJECT CANDIDATE FOR PRODUCTION PROMOTION**

#### Promotion Decision Rationale:
1. **Phishing Recall Constraint Violation:** The mandatory production constraint requires phishing recall to remain $\ge 94.00\%$. 
   * Active Production Model (v2.1.0) achieves **$98.34\%$ recall** on this held-out domain-disjoint test set ($415 / 422$ phishing attacks caught).
   * Candidate Model (Ablation C1: Normalized Features) achieves only **$66.11\%$ recall** ($279 / 422$ phishing attacks caught, **$143$ false negatives**).
   * Even when sweeping `scale_pos_weight` up to $10.0$, candidate recall plateaus at **$79.29\%$**, falling far below the $94.00\%$ security threshold.
2. **Failure to Meaningfully Resolve Sparse Legitimate Page FPR:**
   * Candidate C1 sparse legitimate page FPR is **$25.00\%$** (compared to $29.17\%$ for production baseline on this fold), failing to reach the $< 5.00\%$ target.
3. **Core Machine Learning Insight:** Removing the raw `num_internal_links` feature successfully de-concentrated the top 2 features from $44.46\% \implies 34.17\%$ and removed collinearity ($r=0.9717$), but revealed that the model's high recall in v2.1.0 was heavily reliant on the structural disparity between Tranco homepage crawling and PhishTank landing pages. Without replacing this with deeper semantic content features or expanded sparse legitimate training data, tree classifiers under honest domain-disjoint splitting cannot maintain $\ge 94\%$ attack recall.

---

## 2. Quantitative Ablation Comparison

All models trained and evaluated on the exact same 5-fold Domain-Disjoint GroupKFold split ($N=8,911$ total samples, $N=1,783$ test samples, $0.00\%$ domain overlap):

| Evaluation Metric | Production Baseline (v2.1.0) | Ablation A (Baseline Features Retrained) | Ablation B (Without `num_internal_links`) | Ablation C1 (Candidate Normalized Features) | Ablation C2 (Candidate Calibrated Isotonic) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Feature Count** | $43$ features | $43$ features | $42$ features | **$47$ features** | $47$ features |
| **Accuracy** | **$95.79\%$** | $90.58\%$ | $89.68\%$ | $88.50\%$ | $87.44\%$ |
| **Phishing Recall** | **$98.34\%$** ($415 / 422$) | $77.25\%$ ($326 / 422$) | $72.51\%$ ($306 / 422$) | $66.11\%$ ($279 / 422$) | $53.32\%$ ($225 / 422$) |
| **Precision** | $85.92\%$ | $81.91\%$ | $81.82\%$ | $81.82\%$ | **$89.29\%$** |
| **F1-Score** | **$91.71\%$** | $79.51\%$ | $76.88\%$ | $73.13\%$ | $66.77\%$ |
| **Specificity** | $95.00\%$ | $94.71\%$ | $95.00\%$ | $95.44\%$ | **$98.02\%$** |
| **False Positive Rate (FPR)** | $5.00\%$ ($68 / 1361$) | $5.29\%$ ($72 / 1361$) | $5.00\%$ ($68 / 1361$) | $4.56\%$ ($62 / 1361$) | **$1.98\%$** ($27 / 1361$) |
| **False Negative Rate (FNR)** | **$1.66\%$** ($7 / 422$) | $22.75\%$ ($96 / 422$) | $27.49\%$ ($116 / 422$) | $33.89\%$ ($143 / 422$) | $46.68\%$ ($197 / 422$) |
| **ROC-AUC** | **$0.9943$** | $0.9688$ | $0.9691$ | $0.9678$ | $0.9660$ |
| **PR-AUC** | **$0.9880$** | $0.8978$ | $0.8984$ | $0.8955$ | $0.8891$ |
| **Brier Score** | **$0.0282$** | $0.0625$ | $0.0626$ | $0.0674$ | $0.0880$ |
| **Top 2 Feature Concentration**| $44.46\%$ | $44.46\%$ | **$32.95\%$** | **$34.17\%$** | **$31.91\%$** |

---

## 3. Generalization & Subclass Slice Comparison

| Subclass Slice | Production Baseline (v2.1.0) | Ablation A (Baseline Retrained) | Ablation B (No Internal Links) | Ablation C1 (Candidate Normalized) | Ablation C2 (Calibrated) | Target Constraint |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Sparse Legitimate FPR ($\le 20$ links, $N=192$)** | $29.17\%$ ($56$ FPs) | $29.69\%$ ($57$ FPs) | $26.56\%$ ($51$ FPs) | $25.00\%$ ($48$ FPs) | **$11.98\%$** ($23$ FPs) | $< 5.00\%$ |
| **Legitimate Login/SSO FPR ($N=209$)** | $2.39\%$ ($5$ FPs) | $3.35\%$ ($7$ FPs) | $3.83\%$ ($8$ FPs) | $3.35\%$ ($7$ FPs) | **$1.91\%$** ($4$ FPs) | $< 5.00\%$ |
| **Shortened URL Phishing Recall ($N=9$)** | **$88.89\%$** ($8 / 9$) | **$88.89\%$** ($8 / 9$) | **$88.89\%$** ($8 / 9$) | **$88.89\%$** ($8 / 9$) | $77.78\%$ ($7 / 9$) | $\ge 94.00\%$ |
| **HTTPS Phishing Recall ($N=395$)** | **$98.23\%$** ($388 / 395$) | $75.95\%$ ($300 / 395$) | $70.89\%$ ($280 / 395$) | $64.05\%$ ($253 / 395$) | $51.65\%$ ($204 / 395$) | $\ge 94.00\%$ |
| **Sparse Phishing Recall ($\le 20$ links, $N=354$)** | **$99.15\%$** ($351 / 354$) | $77.40\%$ ($274 / 354$) | $71.75\%$ ($254 / 354$) | $63.84\%$ ($226 / 354$) | $53.95\%$ ($191 / 354$) | $\ge 94.00\%$ |

---

## 4. Candidate Feature Engineering & Importance Analysis

### 4.1 Candidate Feature Set (47 Features)
Candidate Model C1 removed collinear `num_internal_links` and added 5 bounded, normalized features:
1. `internal_link_ratio`: $\frac{\text{num\_internal\_links}}{\max(1, \text{num\_links})} \in [0.0, 1.0]$.
2. `external_link_ratio`: $\frac{\text{num\_external\_links}}{\max(1, \text{num\_links})} \in [0.0, 1.0]$.
3. `link_density_per_kb_html`: $\min\left(50.0, \frac{\text{num\_links}}{\max(0.1, \text{html\_size\_kb})}\right)$.
4. `links_per_form`: $\min\left(100.0, \frac{\text{num\_links}}{\text{num\_forms}}\right)$ ($0.0$ if $0$ forms).
5. `links_per_input_field`: $\min\left(100.0, \frac{\text{num\_links}}{\text{num\_input\_fields}}\right)$ ($0.0$ if $0$ inputs).
6. `subdomain_to_apex_length_ratio`: $\min\left(10.0, \frac{\text{subdomain\_len}}{\max(1, \text{apex\_len})}\right)$.

### 4.2 Top 15 Feature Importances in Candidate C1
| Feature Name | Tree Gain Importance | Permutation Importance (Recall Drop) |
| :--- | :--- | :--- |
| **`num_links`** | **$0.2664$** ($26.64\%$) | **$0.0924 \pm 0.0054$** |
| **`domain_length`** | **$0.0753$** ($7.53\%$) | $0.0038 \pm 0.0015$ |
| **`num_external_links`** | **$0.0584$** ($5.84\%$) | $0.0095 \pm 0.0034$ |
| **`internal_link_ratio` (NEW)** | **$0.0530$** ($5.30\%$) | **$0.0412 \pm 0.0024$** |
| **`uses_https`** | **$0.0335$** ($3.35\%$) | $0.0171 \pm 0.0041$ |
| **`num_slashes`** | **$0.0286$** ($2.86\%$) | $0.0028 \pm 0.0018$ |
| **`path_length`** | **$0.0254$** ($2.54\%$) | $0.0038 \pm 0.0019$ |
| **`external_link_ratio`** | **$0.0254$** ($2.54\%$) | $0.0147 \pm 0.0018$ |
| **`num_images`** | **$0.0246$** ($2.46\%$) | $0.0095 \pm 0.0030$ |
| **`link_density_per_kb_html` (NEW)** | **$0.0236$** ($2.36\%$) | $0.0066 \pm 0.0023$ |
| **`subdomain_to_apex_length_ratio` (NEW)** | **$0.0215$** ($2.15\%$) | $0.0038 \pm 0.0010$ |
| **`num_digits`** | **$0.0215$** ($2.15\%$) | **$0.0616 \pm 0.0062$** |
| **`num_scripts`** | **$0.0211$** ($2.11\%$) | $0.0038 \pm 0.0019$ |
| **`links_per_form` (NEW)** | **$0.0210$** ($2.10\%$) | $0.0019 \pm 0.0010$ |
| **`num_dots`** | **$0.0194$** ($1.94\%$) | $0.0052 \pm 0.0018$ |

---

## 5. Experiment Verification Checklist

- [x] **No train/test domain overlap:** Verified $0.00\%$ domain leakage ($0$ overlapping domains between $2,440$ train domains and $609$ test domains).
- [x] **No duplicate URLs across splits:** Verified $0$ duplicate URLs.
- [x] **Feature ordering verified:** `candidate_feature_columns.json` matches model input schema.
- [x] **Model metadata matches artifact:** SHA-256 `e3aacd38aa335aa38befa2844d9e71a466fc6aadf226a4fa625d6984a4c51827`.
- [x] **Live production model remains unchanged:** SHA-256 `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` verified identical.
- [x] **Separate artifact directory:** All artifacts created in `backend/ml/models/candidates_link_density/`.

---

## 6. Reproducibility Command

To re-run the entire candidate experiment from scratch and verify the exact measured metrics:

```powershell
backend\venv\Scripts\python.exe backend\ml\training\train_candidate_link_density.py
```

### Artifact Locations:
* Candidate Model: `backend/ml/models/candidates_link_density/candidate_link_density_model.joblib`
* Candidate Feature Columns: `backend/ml/models/candidates_link_density/candidate_feature_columns.json`
* Candidate Metadata: `backend/ml/models/candidates_link_density/candidate_metadata.json`
* Full JSON Experiment Report: `backend/ml/models/candidates_link_density/candidate_experiment_report.json`
* Permutation Importances: `backend/ml/models/candidates_link_density/candidate_permutation_importances.json`
* Feature Correlations: `backend/ml/models/candidates_link_density/candidate_feature_correlations.json`
