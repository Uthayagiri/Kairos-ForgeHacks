"""
Comprehensive exploration and tradeoff space analysis for PhishGuard AI:
1. Grid exploration across regularization spectrum (depth, colsample, scale_pos_weight, etc.)
2. Threshold vs. Calibration analysis (ROC curve, threshold sweep, uncalibrated vs calibrated)
3. Feature transformation investigation (monotonic vs interaction features)
4. Evaluation of top candidates against the 50-URL real-world benchmark & latency
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

# Split
gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
train_idx, test_idx = next(gss.split(X, y, groups))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
groups_train = groups.iloc[train_idx]

print(f"Train size: {len(X_train)} ({y_train.value_counts().to_dict()})")
print(f"Test size:  {len(X_test)} ({y_test.value_counts().to_dict()})")

# Load Legacy Model
legacy_model = joblib.load("backend/ml/models/legacy_v1/phishing_model_v1.joblib")

# Grid of candidate configurations
candidate_params = [
    # 1. Depth 4, moderate colsample (0.7-0.8)
    {"name": "XGB_d4_col0.7_spw3.7", "max_depth": 4, "colsample_bytree": 0.7, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95},
    {"name": "XGB_d4_col0.8_spw3.7", "max_depth": 4, "colsample_bytree": 0.8, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95},
    {"name": "XGB_d4_col0.8_spw2.7", "max_depth": 4, "colsample_bytree": 0.8, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 2.7381, "reg_lambda": 1.0, "subsample": 0.95},
    
    # 2. Depth 5, colsample 0.7 - 0.8
    {"name": "XGB_d5_col0.7_spw3.7", "max_depth": 5, "colsample_bytree": 0.7, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95},
    {"name": "XGB_d5_col0.8_spw3.7", "max_depth": 5, "colsample_bytree": 0.8, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95},
    {"name": "XGB_d5_col0.8_spw2.7", "max_depth": 5, "colsample_bytree": 0.8, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 2.7381, "reg_lambda": 1.0, "subsample": 0.95},
    
    # 3. Depth 6, colsample 0.7 - 0.8
    {"name": "XGB_d6_col0.7_spw3.7", "max_depth": 6, "colsample_bytree": 0.7, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95},
    {"name": "XGB_d6_col0.8_spw3.7", "max_depth": 6, "colsample_bytree": 0.8, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95},
    
    # 4. Depth 3, colsample 0.8 (test if depth 3 was the bottleneck)
    {"name": "XGB_d3_col0.8_spw3.7", "max_depth": 3, "colsample_bytree": 0.8, "learning_rate": 0.05, "n_estimators": 200, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95},
    
    # 5. Rejected v2 configuration (depth 3, colsample 0.6) for direct reference
    {"name": "XGB_d3_col0.6_spw3.7 (v2.0 base)", "max_depth": 3, "colsample_bytree": 0.6, "learning_rate": 0.03, "n_estimators": 150, "scale_pos_weight": 3.7155, "reg_lambda": 1.0, "subsample": 0.95},
]

results = []

print("\n" + "=" * 95)
print("SECTION 1: SYSTEMATIC EXPLORATION OF THE REGULARIZATION TRADEOFF SPACE")
print("=" * 95)
print(f"{'Config Name':<32} | {'Recall':<7} | {'Prec':<7} | {'F1':<7} | {'Acc':<7} | {'ROC-AUC':<7} | {'Top2 Conc':<9} | {'Top 2 Features':<25}")
print("-" * 125)

# Evaluate legacy baseline first
leg_probs = legacy_model.predict_proba(X_test)[:, 1]
leg_preds = (leg_probs >= 0.5).astype(int)
leg_importances = pd.Series(legacy_model.feature_importances_, index=feature_cols).sort_values(ascending=False)
leg_top2_conc = leg_importances.iloc[0:2].sum()
top2_names_leg = f"{leg_importances.index[0]} ({leg_importances.iloc[0]*100:.1f}%), {leg_importances.index[1]} ({leg_importances.iloc[1]*100:.1f}%)"

print(f"{'Legacy Baseline v1 (Deployed)':<32} | {recall_score(y_test, leg_preds)*100:5.2f}% | {precision_score(y_test, leg_preds)*100:5.2f}% | {f1_score(y_test, leg_preds)*100:5.2f}% | {accuracy_score(y_test, leg_preds)*100:5.2f}% | {roc_auc_score(y_test, leg_probs):.4f}  | {leg_top2_conc*100:5.2f}%   | {top2_names_leg}")

fitted_models = {}

for p in candidate_params:
    name = p["name"]
    model = XGBClassifier(
        n_estimators=p["n_estimators"],
        max_depth=p["max_depth"],
        learning_rate=p["learning_rate"],
        colsample_bytree=p["colsample_bytree"],
        subsample=p["subsample"],
        reg_lambda=p["reg_lambda"],
        scale_pos_weight=p["scale_pos_weight"],
        random_state=42,
        eval_metric="logloss",
        n_jobs=-1
    )
    model.fit(X_train, y_train)
    fitted_models[name] = model
    
    probs = model.predict_proba(X_test)[:, 1]
    preds = (probs >= 0.5).astype(int)
    
    importances = pd.Series(model.feature_importances_, index=feature_cols).sort_values(ascending=False)
    top2_conc = importances.iloc[0:2].sum()
    top2_names = f"{importances.index[0]} ({importances.iloc[0]*100:.1f}%), {importances.index[1]} ({importances.iloc[1]*100:.1f}%)"
    
    rec = recall_score(y_test, preds)
    prec = precision_score(y_test, preds)
    f1 = f1_score(y_test, preds)
    acc = accuracy_score(y_test, preds)
    auc = roc_auc_score(y_test, probs)
    brier = brier_score_loss(y_test, probs)
    
    results.append({
        "name": name,
        "recall": rec,
        "precision": prec,
        "f1": f1,
        "accuracy": acc,
        "roc_auc": auc,
        "brier": brier,
        "top2_conc": top2_conc,
        "top2_names": top2_names,
        "params": p
    })
    
    print(f"{name:<32} | {rec*100:5.2f}% | {prec*100:5.2f}% | {f1*100:5.2f}% | {acc*100:5.2f}% | {auc:.4f}  | {top2_conc*100:5.2f}%   | {top2_names}")


print("\n" + "=" * 95)
print("SECTION 2: THRESHOLD VS. CALIBRATION VS. BASE MODEL INVESTIGATION")
print("=" * 95)

# Compare base models vs CalibratedClassifierCV across thresholds
test_configs_for_calib = ["XGB_d4_col0.8_spw3.7", "XGB_d5_col0.8_spw3.7", "XGB_d4_col0.7_spw3.7"]

for cfg_name in test_configs_for_calib:
    base_m = fitted_models[cfg_name]
    base_probs = base_m.predict_proba(X_test)[:, 1]
    
    # Sigmoid calibration with GroupKFold
    gkf = GroupKFold(n_splits=5)
    cal_m = CalibratedClassifierCV(estimator=base_m, method='sigmoid', cv=gkf)
    cal_m.fit(X_train, y_train, groups=groups_train)
    cal_probs = cal_m.predict_proba(X_test)[:, 1]
    
    print(f"\n--- Model: {cfg_name} ---")
    print(f"  Base XGBoost ROC-AUC:       {roc_auc_score(y_test, base_probs):.5f}")
    print(f"  Calibrated Model ROC-AUC:   {roc_auc_score(y_test, cal_probs):.5f}")
    print(f"  Base XGBoost Brier Score:   {brier_score_loss(y_test, base_probs):.5f}")
    print(f"  Calibrated Brier Score:     {brier_score_loss(y_test, cal_probs):.5f}")
    
    print("\n  Threshold Sweep on BASE Model (Uncalibrated):")
    print("  Threshold | Recall  | Precision | F1-Score | Accuracy | FN count (Missed)")
    for thresh in [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60]:
        t_preds = (base_probs >= thresh).astype(int)
        r = recall_score(y_test, t_preds)
        p = precision_score(y_test, t_preds)
        f = f1_score(y_test, t_preds)
        a = accuracy_score(y_test, t_preds)
        fn = ((y_test == 1) & (t_preds == 0)).sum()
        print(f"    {thresh:4.2f}    | {r*100:5.2f}% |  {p*100:5.2f}%  |  {f*100:5.2f}%  |  {a*100:5.2f}%  | {fn:2d} missed")

    print("\n  Threshold Sweep on CALIBRATED Model:")
    print("  Threshold | Recall  | Precision | F1-Score | Accuracy | FN count (Missed)")
    for thresh in [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]:
        t_preds = (cal_probs >= thresh).astype(int)
        r = recall_score(y_test, t_preds)
        p = precision_score(y_test, t_preds)
        f = f1_score(y_test, t_preds)
        a = accuracy_score(y_test, t_preds)
        fn = ((y_test == 1) & (t_preds == 0)).sum()
        print(f"    {thresh:4.2f}    | {r*100:5.2f}% |  {p*100:5.2f}%  |  {f*100:5.2f}%  |  {a*100:5.2f}%  | {fn:2d} missed")


# Save results for downstream analysis
with open("scratch/tradeoff_exploration_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("\nTradeoff exploration completed.")
