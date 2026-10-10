# Implementation & Diagnostic Audit: EXP-16

## Root Cause Analysis for EXP-15 Near-Identical Predictions

### 1. The Rendering Dataset Was Truncated (`idx < 1000`)
In EXP-14 (`scratch/dynamic_content_feature_fusion/scripts/run_experiment.py` line 290), the rendering loop contained a loop guard `and idx < 1000`.
As a result, only samples in the first 1,000 dataset rows were rendered. The remaining 7,910 samples (including 88.8% of test set samples) were assigned `delta_num_links = 0` and static feature fallbacks.

### 2. Candidates B–E and G Never Evaluated Rendered Features on XGBoost
In EXP-15 (`scratch/selective_rendering_threshold_tuning/scripts/run_experiment.py`), Candidates B, C, D, E, and G calculated static probabilities `s1 = prod_model.predict_proba(test_df[PROD_FEATURES])[:, 1]`.
When a trigger fired, the candidate did **not** re-run `prod_model.predict_proba(x_rendered)`. Instead, it executed:
```python
if delta_links >= 10 and strong_veto == 0:
    pred = 0
    prob = 0.30
else:
    pred = (s1 >= 0.50)
```
Because `delta_links` was 0 for unrendered rows and `< 10` for most others, the candidate predictions were 100% identical to baseline static predictions.

### 3. Model Input Verification
- In production inference (`backend/app/services/detection_engine.py`), the model receives a dictionary mapped to the exact 43 features.
- To measure the true effect of rendering, the 43-feature vector extracted from the rendered DOM MUST be passed directly to `prod_model.predict_proba()`.
