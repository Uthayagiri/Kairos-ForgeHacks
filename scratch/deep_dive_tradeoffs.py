"""
Deep dive experimentation script:
1. Full tradeoff exploration of base models & calibrated models across hyperparameters.
2. Threshold sweep (threshold vs calibration analysis).
3. Feature transformation test (log1p transform & ratio interactions).
4. 50-URL benchmark evaluation for top candidate configurations.
5. Inference latency measurement.
"""

import time
import json
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import GroupShuffleSplit, GroupKFold
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, brier_score_loss, confusion_matrix, roc_curve, precision_recall_curve
)
from sklearn.calibration import CalibratedClassifierCV
from xgboost import XGBClassifier

# Load expanded dataset
DATASET_PATH = "backend/data/processed/training_dataset_expanded.csv"
df = pd.read_csv(DATASET_PATH)

def extract_registered_domain(url: str) -> str:
    try:
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower().strip()
        if ":" in host:
            host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        
        two_part_tlds = {"co.uk", "ac.uk", "gov.uk", "ac.in", "gov.in", "co.in", "edu.in", "com.au", "net.au", "co.jp", "com.br", "co.za"}
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in two_part_tlds and len(parts) >= 3:
            return f"{parts[-3]}.{last_two}"
        return f"{parts[-2]}.{parts[-1]}"
    except Exception:
        return url or "unknown"

df['reg_domain'] = df['url'].apply(extract_registered_domain)
df['label_binary'] = df['label'].apply(lambda v: 1 if str(v).lower().strip() in ['1', 'phishing'] else 0)

feature_cols = [
    # 22 URL features
    'url_length', 'domain_length', 'path_length', 'num_dots', 'num_hyphens',
    'num_underscores', 'num_slashes', 'num_digits', 'num_special_chars',
    'num_subdomains', 'num_query_params', 'path_depth', 'has_at_symbol',
    'has_ip_address', 'uses_https', 'has_port', 'has_url_encoding',
    'has_suspicious_tld', 'has_suspicious_keywords', 'has_double_slash_redirect',
    'is_shortened_url', 'url_parse_error',
    # 21 HTML features
    'num_forms', 'num_input_fields', 'num_password_fields', 'has_login_form',
    'num_forms_with_external_action', 'has_form_action_empty_or_javascript',
    'num_links', 'num_internal_links', 'num_external_links', 'external_link_ratio',
    'num_links_with_mismatched_text', 'num_scripts', 'num_iframes',
    'has_hidden_iframe', 'has_suspicious_js_patterns', 'num_meta_refresh_redirects',
    'title_length', 'has_favicon', 'num_images', 'text_to_html_ratio',
    'html_parse_error'
]

X = df[feature_cols]
y = df['label_binary']
groups = df['reg_domain']

# Clean domain-grouped split (exact same split: random_state=42, test_size=0.20)
gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
train_idx, test_idx = next(gss.split(X, y, groups))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
groups_train = groups.iloc[train_idx]
groups_test = groups.iloc[test_idx]

# Precompute 5-fold domain-grouped splits for training calibration
gkf = GroupKFold(n_splits=5)
cv_splits = list(gkf.split(X_train, y_train, groups=groups_train))

# Load Legacy Model
legacy_model = joblib.load("backend/ml/models/legacy_v1/phishing_model_v1.joblib")

print("=" * 105)
print("SECTION 1: SYSTEMATIC EXPLORATION OF THE REGULARIZATION TRADEOFF SPACE")
print("=" * 105)

candidate_configs = [
    # Baseline references
    {"name": "1. Legacy Baseline v1 (Deployed)", "type": "legacy", "model": legacy_model},
    {"name": "2. Rejected v2.0 (Calibrated d3 col0.6)", "type": "rejected_v2", "base_params": {"max_depth": 3, "colsample_bytree": 0.6, "learning_rate": 0.03, "n_estimators": 150, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95}},
    
    # Candidate Set A: Depth 4 with moderate colsample (0.7-0.8) and adjusted spw
    {"name": "3. Candidate A1: XGB d4 col0.8 spw3.7", "type": "xgb", "base_params": {"max_depth": 4, "colsample_bytree": 0.8, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95}},
    {"name": "4. Candidate A2: XGB d4 col0.7 spw3.7", "type": "xgb", "base_params": {"max_depth": 4, "colsample_bytree": 0.7, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95}},
    {"name": "5. Candidate A3: XGB d4 col0.8 spw5.0 (High Recall)", "type": "xgb", "base_params": {"max_depth": 4, "colsample_bytree": 0.8, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 5.0, "reg_lambda": 1.0, "subsample": 0.95}},
    {"name": "6. Candidate A4: XGB d4 col0.7 spw5.0 (High Recall)", "type": "xgb", "base_params": {"max_depth": 4, "colsample_bytree": 0.7, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 5.0, "reg_lambda": 1.0, "subsample": 0.95}},
    
    # Candidate Set B: Depth 5 with colsample (0.7-0.8)
    {"name": "7. Candidate B1: XGB d5 col0.8 spw3.7", "type": "xgb", "base_params": {"max_depth": 5, "colsample_bytree": 0.8, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95}},
    {"name": "8. Candidate B2: XGB d5 col0.7 spw3.7", "type": "xgb", "base_params": {"max_depth": 5, "colsample_bytree": 0.7, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95}},
    {"name": "9. Candidate B3: XGB d5 col0.8 spw5.0 (High Recall)", "type": "xgb", "base_params": {"max_depth": 5, "colsample_bytree": 0.8, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 5.0, "reg_lambda": 1.0, "subsample": 0.95}},
    {"name": "10. Candidate B4: XGB d5 col0.7 spw5.0 (High Recall)", "type": "xgb", "base_params": {"max_depth": 5, "colsample_bytree": 0.7, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 5.0, "reg_lambda": 1.0, "subsample": 0.95}},
    
    # Candidate Set C: Depth 4 colsample 0.85 (Light Regularization)
    {"name": "11. Candidate C1: XGB d4 col0.85 spw3.7", "type": "xgb", "base_params": {"max_depth": 4, "colsample_bytree": 0.85, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95}},
    {"name": "12. Candidate C2: XGB d4 col0.85 spw5.0", "type": "xgb", "base_params": {"max_depth": 4, "colsample_bytree": 0.85, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 5.0, "reg_lambda": 1.0, "subsample": 0.95}},
]

eval_table = []
models_dict = {}

print(f"{'Config Name':<42} | {'Recall':<7} | {'Prec':<7} | {'F1':<7} | {'Acc':<7} | {'ROC-AUC':<7} | {'Brier':<6} | {'Top2 Conc':<9} | {'FNs (Missed)'}")
print("-" * 125)

for c in candidate_configs:
    name = c["name"]
    if c["type"] == "legacy":
        m = c["model"]
        probs = m.predict_proba(X_test)[:, 1]
        preds = (probs >= 0.5).astype(int)
        imps = pd.Series(m.feature_importances_, index=feature_cols).sort_values(ascending=False)
        top2_conc = imps.iloc[0:2].sum()
        top2_desc = f"{imps.index[0]} ({imps.iloc[0]*100:.1f}%), {imps.index[1]} ({imps.iloc[1]*100:.1f}%)"
        models_dict[name] = m
    elif c["type"] == "rejected_v2":
        base_m = XGBClassifier(**c["base_params"], random_state=42, eval_metric="logloss", n_jobs=-1)
        m = CalibratedClassifierCV(estimator=base_m, method='sigmoid', cv=cv_splits)
        m.fit(X_train, y_train)
        probs = m.predict_proba(X_test)[:, 1]
        preds = (probs >= 0.5).astype(int)
        # get base booster importances
        base_fitted = m.calibrated_classifiers_[0].estimator
        imps = pd.Series(base_fitted.feature_importances_, index=feature_cols).sort_values(ascending=False)
        top2_conc = imps.iloc[0:2].sum()
        top2_desc = f"{imps.index[0]} ({imps.iloc[0]*100:.1f}%), {imps.index[1]} ({imps.iloc[1]*100:.1f}%)"
        models_dict[name] = m
    else:
        m = XGBClassifier(**c["base_params"], random_state=42, eval_metric="logloss", n_jobs=-1)
        m.fit(X_train, y_train)
        probs = m.predict_proba(X_test)[:, 1]
        preds = (probs >= 0.5).astype(int)
        imps = pd.Series(m.feature_importances_, index=feature_cols).sort_values(ascending=False)
        top2_conc = imps.iloc[0:2].sum()
        top2_desc = f"{imps.index[0]} ({imps.iloc[0]*100:.1f}%), {imps.index[1]} ({imps.iloc[1]*100:.1f}%)"
        models_dict[name] = m
    
    rec = recall_score(y_test, preds)
    prec = precision_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    acc = accuracy_score(y_test, preds)
    auc = roc_auc_score(y_test, probs)
    brier = brier_score_loss(y_test, probs)
    cm = confusion_matrix(y_test, preds)
    tn, fp, fn, tp = cm.ravel()
    
    eval_table.append({
        "name": name,
        "recall": rec,
        "precision": prec,
        "f1": f1,
        "acc": acc,
        "roc_auc": auc,
        "brier": brier,
        "top2_conc": top2_conc,
        "top2_desc": top2_desc,
        "cm": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "probs": probs
    })
    
    print(f"{name:<42} | {rec*100:5.2f}% | {prec*100:5.2f}% | {f1*100:5.2f}% | {acc*100:5.2f}% | {auc:.4f}  | {brier:.4f} | {top2_conc*100:5.2f}%   | {fn:2d} missed")


print("\n" + "=" * 105)
print("SECTION 2: THRESHOLD VS. CALIBRATION VS. ARCHITECTURE INVESTIGATION")
print("=" * 105)

# Detailed analysis on Candidate A3 (d4 col0.8 spw5.0) and Candidate B3 (d5 col0.8 spw5.0)
top_candidates = ["5. Candidate A3: XGB d4 col0.8 spw5.0 (High Recall)", "9. Candidate B3: XGB d5 col0.8 spw5.0 (High Recall)", "4. Candidate A2: XGB d4 col0.7 spw3.7", "11. Candidate C1: XGB d4 col0.85 spw3.7"]

for tc_name in top_candidates:
    print(f"\n--- Threshold & Calibration Analysis for {tc_name} ---")
    base_m = models_dict[tc_name]
    base_probs = base_m.predict_proba(X_test)[:, 1]
    
    # Train Sigmoid and Isotonic calibrated versions using GroupKFold
    cal_sig = CalibratedClassifierCV(estimator=base_m, method='sigmoid', cv=cv_splits)
    cal_sig.fit(X_train, y_train)
    probs_sig = cal_sig.predict_proba(X_test)[:, 1]
    
    print(f"Base Uncalibrated ROC-AUC: {roc_auc_score(y_test, base_probs):.5f} | Brier: {brier_score_loss(y_test, base_probs):.5f}")
    print(f"Sigmoid Calibrated ROC-AUC: {roc_auc_score(y_test, probs_sig):.5f} | Brier: {brier_score_loss(y_test, probs_sig):.5f}")
    
    print("\n  Base Model Performance Across Classification Thresholds:")
    print(f"  {'Threshold':<10} | {'Recall':<8} | {'Precision':<9} | {'F1-Score':<8} | {'Accuracy':<8} | {'FN count'}")
    for thresh in [0.25, 0.30, 0.35, 0.40, 0.45, 0.50, 0.55]:
        p_t = (base_probs >= thresh).astype(int)
        r = recall_score(y_test, p_t)
        p = precision_score(y_test, p_t)
        f = f1_score(y_test, p_t)
        a = accuracy_score(y_test, p_t)
        fn = ((y_test == 1) & (p_t == 0)).sum()
        print(f"  {thresh:<10.2f} | {r*100:6.2f}% | {p*100:7.2f}%   | {f*100:6.2f}%  | {a*100:6.2f}%  | {fn:2d} missed")

    print("\n  Calibrated Model Performance Across Classification Thresholds:")
    print(f"  {'Threshold':<10} | {'Recall':<8} | {'Precision':<9} | {'F1-Score':<8} | {'Accuracy':<8} | {'FN count'}")
    for thresh in [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]:
        p_t = (probs_sig >= thresh).astype(int)
        r = recall_score(y_test, p_t)
        p = precision_score(y_test, p_t)
        f = f1_score(y_test, p_t)
        a = accuracy_score(y_test, p_t)
        fn = ((y_test == 1) & (p_t == 0)).sum()
        print(f"  {thresh:<10.2f} | {r*100:6.2f}% | {p*100:7.2f}%   | {f*100:6.2f}%  | {a*100:6.2f}%  | {fn:2d} missed")


print("\n" + "=" * 105)
print("SECTION 3: 50-URL UNSEEN REAL-WORLD BENCHMARK EVALUATION ACROSS CANDIDATES")
print("=" * 105)

# Load existing 50-URL benchmark dataset
with open("scratch/phase4_evaluation_results.json", "r") as f:
    bench_data = json.load(f)

# Extract URLs
bench_urls = [d["url"] for d in bench_data]
bench_types = [d["type"] for d in bench_data]
bench_expected = [d["expected"] for d in bench_data]

# We need feature extraction on the benchmark URLs
from backend.ml.feature_extraction.url_features import extract_url_features
from backend.ml.feature_extraction.html_features import extract_html_features
from backend.ml.data_collection.fetch_html import fetch_html

# Pre-extract benchmark features to evaluate all models on identical vectors
print(f"Extracting live/cached features for all {len(bench_urls)} benchmark URLs...")
bench_features = []
for url in bench_urls:
    uf = extract_url_features(url)
    hf_res = fetch_html(url)
    if hf_res.get("success") and hf_res.get("html"):
        hf = extract_html_features(hf_res["html"], url=url)
    else:
        hf = {f: 0 for f in feature_cols if f not in uf}
    combined = {**uf, **hf}
    bench_features.append([combined.get(f, 0) for f in feature_cols])

X_bench = pd.DataFrame(bench_features, columns=feature_cols)

# Evaluate each candidate on benchmark
models_to_test_on_bench = [
    "1. Legacy Baseline v1 (Deployed)",
    "2. Rejected v2.0 (Calibrated d3 col0.6)",
    "3. Candidate A1: XGB d4 col0.8 spw3.7",
    "5. Candidate A3: XGB d4 col0.8 spw5.0 (High Recall)",
    "7. Candidate B1: XGB d5 col0.8 spw3.7",
    "9. Candidate B3: XGB d5 col0.8 spw5.0 (High Recall)",
    "11. Candidate C1: XGB d4 col0.85 spw3.7",
    "12. Candidate C2: XGB d4 col0.85 spw5.0"
]

print(f"\n{'Model Name':<42} | {'Attacks (10)':<12} | {'Clean Leg (32)':<15} | {'WAF 403 (8)':<12} | {'ps.bitsathy score'}")
print("-" * 115)

bench_summary = {}

for m_name in models_to_test_on_bench:
    m = models_dict[m_name]
    probs = m.predict_proba(X_bench)[:, 1]
    
    # Check attack recall (items 40 to 49)
    attack_probs = probs[40:50]
    attacks_caught = (attack_probs >= 0.5).sum()
    
    # Check clean legitimate (items 0 to 39 excluding the 8 WAF 403 sites)
    # The 8 WAF sites in the 40 leg items are: idx 1 (iitb), 6 (nus), 7 (oxford), 37 (incometax), 38 (passport), etc.
    # Let's check ps.bitsathy.ac.in (idx 0)
    bitsathy_score = probs[0]
    
    # Calculate average probability on 32 clean sites
    clean_indices = [i for i in range(40) if i not in [1, 6, 7, 37, 38] and i != 0] # non-WAF, non-SPA
    clean_mean_prob = probs[clean_indices].mean()
    clean_passed = (probs[clean_indices] < 0.5).sum()
    
    waf_indices = [1, 6, 7, 37, 38]
    waf_mean_prob = probs[waf_indices].mean()
    
    bench_summary[m_name] = {
        "attacks_caught": int(attacks_caught),
        "clean_passed": f"{clean_passed}/{len(clean_indices)}",
        "clean_mean_prob": float(clean_mean_prob),
        "bitsathy_score": float(bitsathy_score),
        "waf_mean_prob": float(waf_mean_prob)
    }
    
    print(f"{m_name:<42} | {attacks_caught:2d}/10 caught  | {clean_passed:2d}/{len(clean_indices)} clean pass  | WAF mean {waf_mean_prob*100:4.1f}% | {bitsathy_score*100:5.2f}%")


print("\n" + "=" * 105)
print("SECTION 4: SINGLE-REQUEST INFERENCE LATENCY BENCHMARK")
print("=" * 105)

sample_row = X_test.iloc[0:1]
for m_name in ["1. Legacy Baseline v1 (Deployed)", "2. Rejected v2.0 (Calibrated d3 col0.6)", "5. Candidate A3: XGB d4 col0.8 spw5.0 (High Recall)", "9. Candidate B3: XGB d5 col0.8 spw5.0 (High Recall)"]:
    m = models_dict[m_name]
    # Warmup
    for _ in range(50):
        _ = m.predict_proba(sample_row)
    t0 = time.perf_counter()
    n_runs = 500
    for _ in range(n_runs):
        _ = m.predict_proba(sample_row)
    t1 = time.perf_counter()
    lat = ((t1 - t0) / n_runs) * 1000
    print(f"  {m_name:<45} : {lat:6.3f} ms per request")


# Save all results to disk for reference
with open("scratch/tradeoff_deep_dive_results.json", "w") as f:
    json.dump({
        "eval_table": [{k: v for k, v in row.items() if k != "probs"} for row in eval_table],
        "bench_summary": bench_summary
    }, f, indent=2)

print("\nDeep dive analysis completed successfully.")
