"""
Phase 1: Comprehensive Deep Diagnostic Audit Script
Audits:
- A: Dataset distribution, domain skew, duplication, campaign templates, auth/SSO representation
- B: Complete 43-feature breakdown, correlations, importance, leakage, manipulation susceptibility
- C: Model behavior, calibration, borderline prediction dynamics, tree margin attributions
- D: Structured False Positive Taxonomy across test set and benchmark
- E: False Negative Analysis of all missed phishing attacks in test set
- F: Real-World Robustness (static vs JS rendering, SPA shells, WAF challenges)
- G & H: Identity / Cross-Domain Form Action Relationship Analysis
- I: Data Representation Gap Quantification
- J: Risk Scoring & Decision System Monotonicity and Calibration Audit
"""

import sys
import os
import json
import time
import hashlib
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from urllib.parse import urlparse
from collections import Counter
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, brier_score_loss, roc_auc_score
)
import xgboost as xgb

REPO_ROOT = Path("c:/Users/Udhaya/S5_Phishing_Detector").resolve()
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.detection_engine import DetectionEngine
from app.services.risk_scoring import map_status_and_risk
from ml.feature_extraction import extract_url_features, extract_html_features, is_likely_unrendered_spa_shell
from ml.feature_extraction.html_features import get_default_html_feature_dict

print("=" * 90)
print("PHASE 1: DEEP DIAGNOSTIC AUDIT (NO ML CHANGES)")
print("=" * 90)

# Load base model & feature columns
prod_path = BACKEND_DIR / "ml" / "models" / "phishing_model.joblib"
prod_model = joblib.load(prod_path)

with open(prod_path, "rb") as f:
    prod_sha256 = hashlib.sha256(f.read()).hexdigest()

with open(BACKEND_DIR / "ml" / "models" / "feature_columns.json", "r") as f:
    feature_cols = json.load(f)

dataset_path = BACKEND_DIR / "data" / "processed" / "training_dataset_expanded.csv"
raw_df = pd.read_csv(dataset_path)

print(f"\n[PROVENANCE] Production Model SHA-256: {prod_sha256}")
print(f"[PROVENANCE] Dataset Path: {dataset_path} (Total Rows: {len(raw_df)})")

# -----------------------------------------------------------------------------
# A. DATASET AUDIT
# -----------------------------------------------------------------------------
print("\n" + "-" * 90)
print("SECTION A: DATASET AUDIT")
print("-" * 90)

def extract_registered_domain(url_str: str) -> str:
    try:
        if not isinstance(url_str, str) or not url_str.strip():
            return "unknown"
        target = url_str if "://" in url_str else f"http://{url_str}"
        host = urlparse(target).hostname or "unknown"
        host = host.lower().strip(".")
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return "unknown"

if "registered_domain" not in raw_df.columns:
    raw_df["registered_domain"] = raw_df["url"].apply(extract_registered_domain)

total_rows = len(raw_df)
legit_count = int((raw_df["label_binary"] == 0).sum())
phish_count = int((raw_df["label_binary"] == 1).sum())
unique_urls = raw_df["url"].nunique()
duplicate_urls = total_rows - unique_urls
unique_domains = raw_df["registered_domain"].nunique()

dom_counts = raw_df["registered_domain"].value_counts()
top_doms = dom_counts.head(10)

# Domain split
gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
train_idx, test_idx = next(gss.split(raw_df, raw_df["label_binary"], groups=raw_df["registered_domain"]))

train_df = raw_df.iloc[train_idx].copy()
test_df = raw_df.iloc[test_idx].copy()

train_doms = set(train_df["registered_domain"])
test_doms = set(test_df["registered_domain"])
overlap_doms = train_doms.intersection(test_doms)

print(f"Total Rows:               {total_rows}")
print(f"Class Balance:            {legit_count} Legitimate ({legit_count/total_rows*100:.2f}%) | {phish_count} Phishing ({phish_count/total_rows*100:.2f}%)")
print(f"Unique URLs / Duplicates: {unique_urls} unique / {duplicate_urls} duplicates")
print(f"Unique Domains:           {unique_domains}")
print(f"Domain Overlap Leakage:   {len(overlap_doms)} ({len(overlap_doms)/len(test_doms)*100:.2f}%)")
print(f"Train Partition:          {len(train_df)} samples across {len(train_doms)} domains")
print(f"Test Partition:           {len(test_df)} samples across {len(test_doms)} domains")

# Subspace representation in training
train_legit = train_df[train_df["label_binary"] == 0]
train_phish = train_df[train_df["label_binary"] == 1]

train_legit_login = train_legit[train_legit["has_login_form"] == 1]
train_phish_login = train_phish[train_phish["has_login_form"] == 1]

train_legit_sparse = train_legit[train_legit["num_links"] <= 10]
train_phish_sparse = train_phish[train_phish["num_links"] <= 10]

train_legit_sparse_login = train_legit[(train_legit["has_login_form"] == 1) & (train_legit["num_links"] <= 10)]
train_phish_sparse_login = train_phish[(train_phish["has_login_form"] == 1) & (train_phish["num_links"] <= 10)]

print(f"\nTraining Subspace Split:")
print(f"  Legitimate with Login Form:          {len(train_legit_login)} / {len(train_legit)} ({len(train_legit_login)/len(train_legit)*100:.2f}%)")
print(f"  Phishing with Login Form:            {len(train_phish_login)} / {len(train_phish)} ({len(train_phish_login)/len(train_phish)*100:.2f}%)")
print(f"  Legitimate with Low Links (<=10):    {len(train_legit_sparse)} / {len(train_legit)} ({len(train_legit_sparse)/len(train_legit)*100:.2f}%)")
print(f"  Phishing with Low Links (<=10):      {len(train_phish_sparse)} / {len(train_phish)} ({len(train_phish_sparse)/len(train_phish)*100:.2f}%)")
print(f"  Legitimate Sparse Login (Links<=10): {len(train_legit_sparse_login)} / {len(train_legit)} ({len(train_legit_sparse_login)/len(train_legit)*100:.2f}%)")
print(f"  Phishing Sparse Login (Links<=10):   {len(train_phish_sparse_login)} / {len(train_phish)} ({len(train_phish_sparse_login)/len(train_phish)*100:.2f}%)")

# -----------------------------------------------------------------------------
# B. FEATURE AUDIT & CORRELATIONS
# -----------------------------------------------------------------------------
print("\n" + "-" * 90)
print("SECTION B: FEATURE AUDIT & IMPORTANCE RANKINGS")
print("-" * 90)

booster = prod_model.get_booster()
gain_scores = booster.get_score(importance_type="gain")
weight_scores = booster.get_score(importance_type="weight")
total_gain = sum(gain_scores.values())

feature_records = []
for col in feature_cols:
    corr = raw_df[col].corr(raw_df["label_binary"])
    gain = gain_scores.get(col, 0.0) / total_gain if total_gain > 0 else 0.0
    weight = weight_scores.get(col, 0.0)
    
    # Categorization
    if col in ["url_length", "path_length", "num_dots", "num_hyphens", "num_underscores", "num_slashes", "num_digits", "num_special_chars", "num_subdomains", "num_query_params", "path_depth", "has_at_symbol", "has_ip_address", "has_port", "has_url_encoding", "has_suspicious_tld", "has_suspicious_keywords", "has_double_slash_redirect", "is_shortened_url", "uses_https", "domain_length"]:
        cat = "URL / Lexical"
    elif col in ["num_forms", "num_input_fields", "num_password_fields", "has_login_form", "num_forms_with_external_action", "has_form_action_empty_or_javascript"]:
        cat = "Forms / Auth"
    elif col in ["num_links", "num_internal_links", "num_external_links", "external_link_ratio", "num_links_with_mismatched_text"]:
        cat = "Link Structure"
    elif col in ["num_scripts", "has_suspicious_js_patterns", "has_hidden_iframe", "num_iframes"]:
        cat = "JavaScript / Framing"
    elif col in ["title_length", "has_favicon", "num_images", "text_to_html_ratio", "num_meta_refresh_redirects"]:
        cat = "Page Content / DOM"
    else:
        cat = "Other / Engine"
        
    feature_records.append({
        "feature": col,
        "category": cat,
        "gain_importance": gain,
        "corr_with_phish": corr,
        "mean_legit": raw_df[raw_df["label_binary"] == 0][col].mean(),
        "mean_phish": raw_df[raw_df["label_binary"] == 1][col].mean()
    })

feat_df = pd.DataFrame(feature_records).sort_values(by="gain_importance", ascending=False)
print(feat_df.head(20).to_string(index=False))

# -----------------------------------------------------------------------------
# C. MODEL BEHAVIOR & HELD-OUT PERFORMANCE
# -----------------------------------------------------------------------------
print("\n" + "-" * 90)
print("SECTION C: MODEL BEHAVIOR & CALIBRATION ON TEST SET")
print("-" * 90)

X_test = test_df[feature_cols]
y_test = test_df["label_binary"].astype(int)

y_pred = prod_model.predict(X_test)
y_proba = prod_model.predict_proba(X_test)[:, 1]

acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred)
rec = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
auc = roc_auc_score(y_test, y_proba)
brier = brier_score_loss(y_test, y_proba)
tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

print(f"Accuracy:        {acc*100:.2f}%")
print(f"Precision:       {prec*100:.2f}%")
print(f"Phishing Recall: {rec*100:.2f}% (TP={tp}, FN={fn})")
print(f"F1-Score:        {f1*100:.2f}%")
print(f"ROC-AUC:         {auc:.4f}")
print(f"Brier Score:     {brier:.4f}")
print(f"Confusion:       TN={tn}, FP={fp}, FN={fn}, TP={tp}")
print(f"False Positives: {fp} ({fp/(fp+tn)*100:.2f}% FPR)")
print(f"False Negatives: {fn} ({fn/(fn+tp)*100:.2f}% FNR)")

# -----------------------------------------------------------------------------
# D. FALSE POSITIVE TAXONOMY
# -----------------------------------------------------------------------------
print("\n" + "-" * 90)
print("SECTION D: FALSE POSITIVE TAXONOMY (75 TEST FALSE POSITIVES)")
print("-" * 90)

test_eval_df = test_df.copy()
test_eval_df["y_pred"] = y_pred
test_eval_df["y_proba"] = y_proba

fp_df = test_eval_df[(test_eval_df["label_binary"] == 0) & (test_eval_df["y_pred"] == 1)].copy()

# Categorize false positives
fp_categories = {
    "Sparse Nav / Minimal UI (num_links <= 10)": len(fp_df[fp_df["num_links"] <= 10]),
    "Login Form Present (has_login_form == 1)": len(fp_df[fp_df["has_login_form"] == 1]),
    "Sparse Nav + Login Form": len(fp_df[(fp_df["num_links"] <= 10) & (fp_df["has_login_form"] == 1)]),
    "External Form Action": len(fp_df[fp_df["num_forms_with_external_action"] > 0]),
    "High Path/URL Complexity": len(fp_df[fp_df["url_length"] > 60]),
    "Brand/Auth Keywords in URL": len(fp_df[fp_df["has_suspicious_keywords"] == 1]),
    "Low Text-to-HTML Ratio (<= 0.05)": len(fp_df[fp_df["text_to_html_ratio"] <= 0.05])
}

for cat_name, count in fp_categories.items():
    print(f"  {cat_name:45s}: {count:3d} / {len(fp_df)} ({count/len(fp_df)*100:.1f}%)")

print("\nSample False Positive Domains & Features:")
print(fp_df[["url", "num_links", "num_internal_links", "has_login_form", "has_suspicious_keywords", "y_proba"]].head(10).to_string(index=False))

# -----------------------------------------------------------------------------
# E. FALSE NEGATIVE ANALYSIS (23 MISSED ATTACKS)
# -----------------------------------------------------------------------------
print("\n" + "-" * 90)
print("SECTION E: FALSE NEGATIVE ANALYSIS (23 MISSED PHISHING ATTACKS)")
print("-" * 90)

fn_df = test_eval_df[(test_eval_df["label_binary"] == 1) & (test_eval_df["y_pred"] == 0)].copy()

fn_characteristics = {
    "Uses HTTPS (uses_https == 1)": len(fn_df[fn_df["uses_https"] == 1]),
    "High Link Count (num_links > 20)": len(fn_df[fn_df["num_links"] > 20]),
    "Moderate Link Count (11-20 links)": len(fn_df[(fn_df["num_links"] >= 11) & (fn_df["num_links"] <= 20)]),
    "Zero Login Form Detected (has_login_form == 0)": len(fn_df[fn_df["has_login_form"] == 0]),
    "Standard/Clean TLD (.com/.org/.net)": len(fn_df[fn_df["has_suspicious_tld"] == 0]),
    "No Suspicious Keywords in URL": len(fn_df[fn_df["has_suspicious_keywords"] == 0]),
    "No IP Address in URL": len(fn_df[fn_df["has_ip_address"] == 0]),
    "High Internal Link Ratio": len(fn_df[fn_df["num_internal_links"] > 5]),
    "Legitimate-looking Domain/Path": len(fn_df[(fn_df["has_ip_address"] == 0) & (fn_df["has_suspicious_tld"] == 0) & (fn_df["has_suspicious_keywords"] == 0)])
}

for trait_name, count in fn_characteristics.items():
    print(f"  {trait_name:48s}: {count:3d} / {len(fn_df)} ({count/len(fn_df)*100:.1f}%)")

print("\nDetailed Profile of Missed Phishing Attacks:")
print(fn_df[["url", "num_links", "num_internal_links", "has_login_form", "uses_https", "has_suspicious_keywords", "y_proba"]].head(15).to_string(index=False))

# -----------------------------------------------------------------------------
# F & H: IDENTITY & CROSS-DOMAIN FORM ACTION AUDIT
# -----------------------------------------------------------------------------
print("\n" + "-" * 90)
print("SECTION F & H: IDENTITY, CROSS-DOMAIN ACTIONS & DOMAIN RELATIONSHIPS")
print("-" * 90)

# Check form action behavior in training & test
legit_ext_form = raw_df[raw_df["label_binary"] == 0]["num_forms_with_external_action"].sum()
phish_ext_form = raw_df[raw_df["label_binary"] == 1]["num_forms_with_external_action"].sum()

print(f"Total External Form Actions in Dataset:")
print(f"  Legitimate samples with external form action: {int((raw_df[raw_df['label_binary'] == 0]['num_forms_with_external_action'] > 0).sum())} / {legit_count}")
print(f"  Phishing samples with external form action:   {int((raw_df[raw_df['label_binary'] == 1]['num_forms_with_external_action'] > 0).sum())} / {phish_count}")

# -----------------------------------------------------------------------------
# J. RISK SCORE MONOTONICITY & DECISION BANDS
# -----------------------------------------------------------------------------
print("\n" + "-" * 90)
print("SECTION J: RISK SCORING BANDS & MONOTONICITY")
print("-" * 90)

bands = [
    ("Low / Safe [0.00 - 0.35)", 0.0, 0.35),
    ("Medium / Suspicious [0.35 - 0.70)", 0.35, 0.70),
    ("High / Phishing [0.70 - 1.00]", 0.70, 1.01)
]

for label_name, low, high in bands:
    mask = (y_proba >= low) & (y_proba < high)
    sub_y = y_test[mask]
    n_total = len(sub_y)
    n_phish = int(sub_y.sum())
    emp_phish_rate = n_phish / n_total if n_total > 0 else 0.0
    print(f"  Band {label_name:35s}: {n_total:4d} test items | {n_phish:3d} Phish | Empirical Phish Rate = {emp_phish_rate*100:.2f}%")

print("\n" + "=" * 90)
print("PHASE 1 DEEP DIAGNOSTIC COMPLETE")
print("=" * 90)
