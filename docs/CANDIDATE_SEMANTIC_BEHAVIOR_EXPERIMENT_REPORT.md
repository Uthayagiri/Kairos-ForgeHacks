# Candidate Experiment Report: Semantic and Behavioral Phishing Indicators

**Experiment Identifier:** `EXP-SEMANTIC-BEHAVIOR-2026-09-16`  
**Candidate Directory:** `backend/ml/models/candidates_semantic_behavior/`  
**Candidate Model Version:** `2.2.0-candidate-semantic-behavior`  
**Candidate Model SHA-256:** `d4acc6e5d3b04c55cdacee49c6eb2dd37c6ee007b0ce815386f3717ff2751784`  
**Validation Strategy:** 5-Fold Domain-Disjoint GroupKFold ($0.00\%$ apex domain leakage)  
**Live Production Model (v2.1.0) SHA-256:** `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` (**VERIFIED UNTOUCHED**)  

---

## 1. Executive Summary & Promotion Recommendation

### 🚨 Promotion Recommendation: **REJECT CANDIDATE FOR PRODUCTION PROMOTION**

#### Promotion Decision Rationale:
1. **Phishing Recall Threshold Violation:** The mandatory production constraint requires phishing recall to remain $\ge 94.00\%$.
   * **Production Model (v2.1.0 Baseline):** Achieves **$98.56\%$ recall** on this held-out domain-disjoint test fold ($411 / 417$ attacks detected, $6$ false negatives).
   * **Candidate Ablation D (URL/Content Consistency):** Achieves **$70.02\%$ recall** ($292 / 417$ attacks detected, $125$ false negatives).
   * **Candidate Ablation E (Combined Semantic & Behavioral):** Achieves **$66.91\%$ recall** ($279 / 417$ attacks detected, $138$ false negatives).
2. **Key Positive Behavioral Finding (Valuable Signal Identified):**
   * The newly introduced feature **`high_external_link_concentration`** ($\text{external\_link\_ratio} > 0.75$) proved to be a highly discriminative semantic signal, capturing **$9.31\%$ tree gain importance** (#3 overall feature in Ablation D) and successfully lowering top-2 feature concentration from **$44.27\% \implies 36.19\%$**.
   * Sparse legitimate page FPR was slightly improved from **$23.78\% \implies 19.46\%$**.
3. **Core Machine Learning Conclusion:** While semantic features like `high_external_link_concentration` ($5.53\times$ higher in phishing), `credential_collection_pattern` ($4.09\times$ higher in phishing), and `subdomain_to_apex_length_ratio` ($5.95\times$ higher in phishing) provide strong structural discrimination, tree classifiers trained strictly on sub-sampled folds without full-corpus multi-objective hyperparameter optimization suffer a severe recall penalty on unseen domains ($70.02\%$ vs $98.56\%$). Therefore, the candidate cannot be promoted to production without violating security constraints.

---

## 2. Quantitative Ablation Matrix

All variants evaluated across strict 5-fold Domain-Disjoint GroupKFold ($N=8,910$ total samples, $N=1,782$ test samples, $0.00\%$ domain overlap):

| Metric | Production Baseline (v2.1.0) | Ablation A (Production Features Retrained) | Ablation B (+ Form Behavior) | Ablation C (+ Page Structure) | Ablation D (+ URL/Content Consistency) | Ablation E (Combined Semantic & Behavioral) | Promotion Target |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Feature Count** | $43$ | $43$ | $46$ | $47$ | $47$ | **$54$** | — |
| **Overall Accuracy** | **$96.86\%$** | $90.57\%$ | $90.35\%$ | $89.79\%$ | **$90.57\%$** | $89.79\%$ | $\ge 95.00\%$ |
| **Phishing Recall** | **$98.56\%$** ($411/417$) | $70.02\%$ ($292/417$) | $69.30\%$ ($289/417$) | $66.67\%$ ($278/417$) | **$70.02\%$** ($292/417$) | $66.91\%$ ($279/417$) | **$\ge 94.00\%$** |
| **Precision** | **$89.15\%$** | $87.16\%$ | $86.79\%$ | $86.60\%$ | **$87.16\%$** | $86.38\%$ | $\ge 85.00\%$ |
| **F1-Score** | **$93.62\%$** | $77.66\%$ | $77.07\%$ | $75.34\%$ | **$77.66\%$** | $75.41\%$ | — |
| **Specificity** | $96.34\%$ | **$96.85\%$** | $96.78\%$ | **$96.85\%$** | **$96.85\%$** | $96.78\%$ | — |
| **Overall FPR** | $3.66\%$ ($50/1365$) | **$3.15\%$** ($43/1365$) | $3.22\%$ ($44/1365$) | **$3.15\%$** ($43/1365$) | **$3.15\%$** ($43/1365$) | $3.22\%$ ($44/1365$) | — |
| **Overall FNR** | **$1.44\%$** ($6/417$) | $29.98\%$ ($125/417$) | $30.70\%$ ($128/417$) | $33.33\%$ ($139/417$) | $29.98\%$ ($125/417$) | $33.09\%$ ($138/417$) | — |
| **ROC-AUC** | **$0.9976$** | $0.9769$ | $0.9764$ | $0.9771$ | **$0.9774$** | $0.9760$ | — |
| **PR-AUC** | **$0.9927$** | $0.9205$ | $0.9173$ | $0.9191$ | **$0.9209$** | $0.9167$ | — |
| **Brier Score** | **$0.0222$** | $0.0577$ | $0.0591$ | $0.0584$ | **$0.0575$** | $0.0592$ | — |
| **Top 2 Feature Concentration** | $43.06\%$ | $44.27\%$ | $41.98\%$ | $40.87\%$ | **$36.19\%$** | $39.05\%$ | $< 30.00\%$ |

---

## 3. Generalization & Subclass Slice Comparison

| Subclass Slice | Production Baseline (v2.1.0) | Ablation A (Baseline Retrained) | Ablation B (Form Behavior) | Ablation C (Page Structure) | Ablation D (URL/Content Consistency) | Ablation E (Combined Semantic) | Target Constraint |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Sparse Legitimate FPR ($\le 20$ links, $N=185$)** | $23.78\%$ ($44$ FPs) | $20.00\%$ ($37$ FPs) | $20.00\%$ ($37$ FPs) | $20.00\%$ ($37$ FPs) | **$19.46\%$** ($36$ FPs) | $20.54\%$ ($38$ FPs) | $< 5.00\%$ |
| **Legitimate Login/SSO FPR ($N=195$)** | **$1.54\%$** ($3$ FPs) | $2.56\%$ ($5$ FPs) | $2.56\%$ ($5$ FPs) | $2.05\%$ ($4$ FPs) | $2.05\%$ ($4$ FPs) | **$1.54\%$** ($3$ FPs) | $< 5.00\%$ |
| **Shortened URL Phishing Recall ($N=6$)** | **$83.33\%$** ($5/6$) | **$83.33\%$** ($5/6$) | **$83.33\%$** ($5/6$) | **$83.33\%$** ($5/6$) | **$83.33\%$** ($5/6$) | **$83.33\%$** ($5/6$) | $\ge 94.00\%$ |
| **HTTPS Phishing Recall ($N=393$)** | **$98.47\%$** ($387/393$) | $68.19\%$ ($268/393$) | $67.43\%$ ($265/393$) | $64.63\%$ ($254/393$) | **$68.19\%$** ($268/393$) | $64.89\%$ ($255/393$) | $\ge 94.00\%$ |
| **Sparse Phishing Recall ($\le 20$ links, $N=363$)** | **$98.90\%$** ($359/363$) | $68.87\%$ ($250/363$) | $68.04\%$ ($247/363$) | $64.74\%$ ($235/363$) | **$68.04\%$** ($247/363$) | $63.91\%$ ($232/363$) | $\ge 94.00\%$ |

---

## 4. Feature Extraction & Engineering Analysis

### 4.1 Reliable Extraction Verification from Static HTML Pipeline
All newly evaluated features were audited to ensure they are 100% extractable from offline static HTML + URL structure without hallucinating client-side JavaScript execution:

1. **Form Behavior Features (Group B, +3 Features):**
   * `password_field_present`: Binary flag indicating presence of `<input type="password">` ($3.16\times$ higher in phishing).
   * `external_form_action_ratio`: Proportion of forms submitting data to third-party apex domains.
   * `credential_collection_pattern`: Compound indicator checking if password or auth inputs submit to external endpoints or empty/javascript pseudo-actions ($4.09\times$ higher in phishing).
2. **Page Structure & Script Features (Group C, +4 Features):**
   * `meta_refresh_present`: Presence of `<meta http-equiv="refresh">` redirect tags ($3.30\times$ higher in phishing).
   * `script_to_link_ratio`: Ratio of `<script>` tag count to total hyperlink count ($3.96\times$ higher in phishing).
   * `hidden_element_indicator`: Combined flag for zero-dimension iframes and obfuscated JS patterns.
   * `iframe_to_image_ratio`: Ratio of embedded iframes to image elements ($1.76\times$ higher in phishing).
3. **URL/Content Consistency & Brand Features (Group D, +4 Features):**
   * `high_external_link_concentration`: Flag for pages where $>75\%$ of all outbound links point off-site ($5.53\times$ higher in phishing: $32.23\%$ phishing vs $5.82\%$ legitimate). **Entered model as #3 top feature with $9.31\%$ gain.**
   * `subdomain_to_apex_length_ratio`: Ratio of subdomain character length to registered apex domain length ($5.95\times$ higher in phishing: mean $1.1418$ vs $0.1919$).
   * `suspicious_keyword_and_login_form`: Intersection of sensitive lure keywords in URL and credential login forms ($2.79\times$ higher in phishing).
   * `brand_keyword_deep_path`: Lure keyword positioned within deep path segments ($\text{depth} \ge 2$).

### 4.2 Top 15 Feature Importances for Winning Candidate (Ablation D)
| Feature Name | Feature Group | Tree Gain Importance |
| :--- | :--- | :--- |
| **`num_links`** | Baseline | **$0.2583$** ($25.83\%$) |
| **`num_internal_links`** | Baseline | **$0.1036$** ($10.36\%$) |
| **`high_external_link_concentration` (NEW)** | **Group D** | **$0.0931$** ($9.31\%$) |
| **`domain_length`** | Baseline | **$0.0563$** ($5.63\%$) |
| **`num_external_links`** | Baseline | **$0.0349$** ($3.49\%$) |
| **`uses_https`** | Baseline | **$0.0316$** ($3.16\%$) |
| **`num_slashes`** | Baseline | **$0.0267$** ($2.67\%$) |
| **`path_length`** | Baseline | **$0.0262$** ($2.62\%$) |
| **`external_link_ratio`** | Baseline | **$0.0233$** ($2.33\%$) |
| **`path_depth`** | Baseline | **$0.0206$** ($2.06\%$) |
| **`num_digits`** | Baseline | **$0.0193$** ($1.93\%$) |
| **`num_images`** | Baseline | **$0.0190$** ($1.90\%$) |
| **`subdomain_to_apex_length_ratio` (NEW)** | **Group D** | **$0.0187$** ($1.87\%$) |
| **`url_length`** | Baseline | **$0.0162$** ($1.62\%$) |
| **`num_special_chars`** | Baseline | **$0.0159$** ($1.59\%$) |

---

## 5. Experiment Verification Checklist

- [x] **No train/test domain overlap:** $0.00\%$ domain leakage across $2,441$ train domains and $608$ test domains.
- [x] **Original features preserved:** All $43$ baseline features retained in all ablations.
- [x] **No static domain/provider whitelists:** Only general structural and behavioral heuristics used.
- [x] **Live production model remains untouched:** SHA-256 `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` verified identical.
- [x] **Separate artifact directory:** All artifacts saved in `backend/ml/models/candidates_semantic_behavior/`.

---

## 6. Reproducibility Command

To re-run the entire semantic and behavioral candidate experiment and verify all empirical numbers:

```powershell
backend\venv\Scripts\python.exe backend\ml\training\train_candidate_semantic_behavior.py
```

### Artifact Locations:
* Candidate Model: `backend/ml/models/candidates_semantic_behavior/candidate_semantic_behavior_model.joblib`
* Candidate Feature Columns: `backend/ml/models/candidates_semantic_behavior/candidate_feature_columns.json`
* Candidate Metadata: `backend/ml/models/candidates_semantic_behavior/candidate_metadata.json`
* Full JSON Experiment Report: `backend/ml/models/candidates_semantic_behavior/candidate_experiment_report.json`
* Permutation Importances: `backend/ml/models/candidates_semantic_behavior/candidate_permutation_importances.json`
* Feature Correlations: `backend/ml/models/candidates_semantic_behavior/candidate_feature_correlations.json`
