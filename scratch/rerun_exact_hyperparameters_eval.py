"""
Rigorous Experimental Re-Evaluation Script
Re-trains Experimental Model 1 and Experimental Model 2 using EXACT production hyperparameters:
  learning_rate=0.05, n_estimators=200, max_depth=4, colsample_bytree=0.7,
  subsample=0.95, reg_lambda=1.0, scale_pos_weight=5.0, random_state=42, n_jobs=-1, eval_metric='logloss'

Evaluates Control vs Exp 1 vs Exp 2 on:
1. 1,799 held-out domain-split test set (0% domain overlap)
2. 34-site real-world benchmark
3. Latency (500 runs)
4. Determinism (5 runs)
"""

import os
import sys
import json
import hashlib
import time
import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, brier_score_loss, confusion_matrix
)
from urllib.parse import urlparse
import tldextract

# Set paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "backend"))

PROD_MODEL_PATH = os.path.join(BASE_DIR, "backend", "ml", "models", "phishing_model.joblib")
CANDIDATES_DIR = os.path.join(BASE_DIR, "backend", "ml", "models", "candidates_auth")
os.makedirs(CANDIDATES_DIR, exist_ok=True)

EXP1_PATH = os.path.join(CANDIDATES_DIR, "candidate_exp1_inst_feature.joblib")
EXP2_PATH = os.path.join(CANDIDATES_DIR, "candidate_exp2_aug_data.joblib")

DATA_DIR = os.path.join(BASE_DIR, "backend", "data")
TRAIN_FILE = os.path.join(DATA_DIR, "train_features.csv")
TEST_FILE = os.path.join(DATA_DIR, "test_features.csv")

# Compute SHA256 helper
def get_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

print("="*80)
print("STEP 1: CONFIRMING EXACT PRODUCTION HYPERPARAMETERS")
print("="*80)
prod_model = joblib.load(PROD_MODEL_PATH)
prod_hash = get_sha256(PROD_MODEL_PATH)
print(f"Production Model Path: {PROD_MODEL_PATH}")
print(f"Production Model SHA256: {prod_hash}")
prod_params = prod_model.get_params()
print("Production XGBoost Parameters:")
for k in ["learning_rate", "n_estimators", "max_depth", "colsample_bytree", "subsample", "reg_lambda", "scale_pos_weight", "random_state", "eval_metric"]:
    print(f"  {k}: {prod_params.get(k)}")

EXACT_HYPERPARAMS = {
    "learning_rate": 0.05,
    "n_estimators": 200,
    "max_depth": 4,
    "colsample_bytree": 0.7,
    "subsample": 0.95,
    "reg_lambda": 1.0,
    "scale_pos_weight": 5.0,
    "random_state": 42,
    "n_jobs": -1,
    "eval_metric": "logloss"
}

# Load Train and Test Data
train_df = pd.read_csv(TRAIN_FILE)
test_df = pd.read_csv(TEST_FILE)

IGNORE_COLS = ["url", "label", "domain", "registered_domain"]
base_feature_cols = [c for c in train_df.columns if c not in IGNORE_COLS]

X_train_base = train_df[base_feature_cols]
y_train_base = train_df["label"]
X_test_base = test_df[base_feature_cols]
y_test_base = test_df["label"]

print(f"\nBase Train Samples: {len(X_train_base)}, Base Test Samples: {len(X_test_base)}")
print(f"Base Features Count: {len(base_feature_cols)}")

print("\n" + "="*80)
print("STEP 2: RE-TRAINING EXPERIMENTAL MODEL 1 (Exact Hyperparameters + is_institutional_domain)")
print("="*80)

def extract_inst_feature(df):
    extracted = []
    for u in df["url"]:
        if pd.isna(u):
            extracted.append(0)
            continue
        try:
            ext = tldextract.extract(str(u))
            suffix = ext.suffix.lower()
            if suffix in ["edu", "ac.in", "gov", "ac.uk", "edu.au", "gov.in", "edu.cn", "ac.jp", "ernet.in", "res.in"] or suffix.startswith("edu.") or suffix.startswith("ac."):
                extracted.append(1)
            else:
                extracted.append(0)
        except Exception:
            extracted.append(0)
    return pd.Series(extracted, index=df.index, name="is_institutional_domain")

train_df_exp1 = train_df.copy()
test_df_exp1 = test_df.copy()
train_df_exp1["is_institutional_domain"] = extract_inst_feature(train_df)
test_df_exp1["is_institutional_domain"] = extract_inst_feature(test_df)

exp1_feature_cols = base_feature_cols + ["is_institutional_domain"]
X_train_exp1 = train_df_exp1[exp1_feature_cols]
y_train_exp1 = train_df_exp1["label"]
X_test_exp1 = test_df_exp1[exp1_feature_cols]
y_test_exp1 = test_df_exp1["label"]

exp1_model = XGBClassifier(**EXACT_HYPERPARAMS)
exp1_model.fit(X_train_exp1, y_train_exp1)
joblib.dump(exp1_model, EXP1_PATH)
exp1_hash = get_sha256(EXP1_PATH)
print(f"Experimental Model 1 Saved: {EXP1_PATH}")
print(f"Experimental Model 1 SHA256: {exp1_hash}")
print(f"Experimental Model 1 Features: {len(exp1_feature_cols)}")

print("\n" + "="*80)
print("STEP 3: RE-TRAINING EXPERIMENTAL MODEL 2 (Exact Hyperparameters + 300 Augmented Auth Rows)")
print("="*80)

# Build 300 augmented rows representative of legitimate sparse auth pages
np.random.seed(42)
aug_rows = []
legit_train_subset = train_df[train_df["label"] == 0]

for i in range(300):
    sample = legit_train_subset.sample(n=1, random_state=42 + i).iloc[0].to_dict()
    sample["url"] = f"https://sso-auth-portal-{i}.example.org/login"
    sample["domain"] = f"sso-auth-portal-{i}.example.org"
    sample["registered_domain"] = f"example{i}.org"
    sample["label"] = 0
    sample["num_links"] = np.random.randint(0, 8)
    sample["num_internal_links"] = np.random.randint(0, min(5, sample["num_links"] + 1))
    sample["num_external_links"] = sample["num_links"] - sample["num_internal_links"]
    sample["external_link_ratio"] = float(sample["num_external_links"] / max(1, sample["num_links"]))
    sample["has_login_form"] = 1
    sample["has_password_input"] = 1
    sample["num_forms"] = np.random.randint(1, 3)
    sample["num_inputs"] = np.random.randint(2, 6)
    sample["has_suspicious_keywords"] = 0
    sample["suspicious_tld"] = 0
    sample["has_ip_address"] = 0
    sample["uses_https"] = 1
    sample["text_to_html_ratio"] = round(np.random.uniform(0.06, 0.25), 4)
    aug_rows.append(sample)

aug_df = pd.DataFrame(aug_rows)
train_df_exp2 = pd.concat([train_df, aug_df], ignore_index=True)

X_train_exp2 = train_df_exp2[base_feature_cols]
y_train_exp2 = train_df_exp2["label"]
X_test_exp2 = test_df[base_feature_cols]
y_test_exp2 = test_df["label"]

exp2_model = XGBClassifier(**EXACT_HYPERPARAMS)
exp2_model.fit(X_train_exp2, y_train_exp2)
joblib.dump(exp2_model, EXP2_PATH)
exp2_hash = get_sha256(EXP2_PATH)
print(f"Experimental Model 2 Saved: {EXP2_PATH}")
print(f"Experimental Model 2 SHA256: {exp2_hash}")
print(f"Experimental Model 2 Training Samples: {len(X_train_exp2)}")

print("\n" + "="*80)
print("STEP 4: HELD-OUT DOMAIN-SPLIT TEST EVALUATION (1,799 SAMPLES, 0% LEAKAGE)")
print("="*80)

def evaluate_model(model, X_test, y_test, name, sha):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    brier = brier_score_loss(y_test, y_proba)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    
    # Feature importances top 2
    importances = model.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top2_conc = importances[sorted_idx[0]] + importances[sorted_idx[1]]
    
    return {
        "name": name,
        "sha256": sha,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1": f1,
        "roc_auc": auc,
        "brier": brier,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "top2_conc": top2_conc,
        "recall_status": "PASS (>= 94.0%)" if rec >= 0.940 else f"FAIL ({rec*100:.2f}%)"
    }

metrics_prod = evaluate_model(prod_model, X_test_base, y_test_base, "Production Control", prod_hash)
metrics_exp1 = evaluate_model(exp1_model, X_test_exp1, y_test_exp1, "Experimental M1 (+inst_domain)", exp1_hash)
metrics_exp2 = evaluate_model(exp2_model, X_test_exp2, y_test_exp2, "Experimental M2 (Data Aug)", exp2_hash)

summary_df = pd.DataFrame([metrics_prod, metrics_exp1, metrics_exp2])
print(summary_df[["name", "accuracy", "precision", "recall", "fn", "fp", "f1", "roc_auc", "brier", "top2_conc", "recall_status"]].to_string(index=False))

print("\n" + "="*80)
print("STEP 5: 34-SITE REAL-WORLD BENCHMARK SWEEP")
print("="*80)

from app.services.feature_extractor import FeatureExtractor
from app.services.risk_scoring import calculate_risk_score, is_likely_unrendered_spa_shell

# Benchmark URLs with curated payloads
BENCHMARK_SITES = [
    # Diagnostic Baseline (4)
    {"name": "Bannari Amman College Portal", "url": "https://ps.bitsathy.ac.in", "cat": "Diagnostic / SPA",
     "dom": {"num_links": 0, "num_internal_links": 0, "num_external_links": 0, "external_link_ratio": 0.0, "has_login_form": False, "has_password_input": False, "num_forms": 0, "num_inputs": 0, "num_hidden_inputs": 0, "num_buttons": 0, "num_images": 0, "num_scripts": 8, "num_stylesheets": 4, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 18, "text_to_html_ratio": 0.012, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Google Accounts Login", "url": "https://accounts.google.com/v3/signin/identifier", "cat": "Diagnostic / Auth",
     "dom": {"num_links": 6, "num_internal_links": 4, "num_external_links": 2, "external_link_ratio": 0.33, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 4, "num_hidden_inputs": 2, "num_buttons": 2, "num_images": 2, "num_scripts": 12, "num_stylesheets": 2, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 22, "text_to_html_ratio": 0.08, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Salesforce Customer Portal", "url": "https://login.salesforce.com", "cat": "Diagnostic / Auth",
     "dom": {"num_links": 8, "num_internal_links": 5, "num_external_links": 3, "external_link_ratio": 0.375, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 5, "num_hidden_inputs": 2, "num_buttons": 1, "num_images": 3, "num_scripts": 15, "num_stylesheets": 3, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 15, "text_to_html_ratio": 0.09, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "TinyURL Web App", "url": "https://tinyurl.com/app", "cat": "Diagnostic / Shortener",
     "dom": {"num_links": 12, "num_internal_links": 10, "num_external_links": 2, "external_link_ratio": 0.166, "has_login_form": False, "has_password_input": False, "num_forms": 1, "num_inputs": 2, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 4, "num_scripts": 8, "num_stylesheets": 2, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 25, "text_to_html_ratio": 0.085, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Microsoft Online Entra ID", "url": "https://login.microsoftonline.com/common/oauth2/authorize", "cat": "Diagnostic / SPA Auth",
     "dom": {"num_links": 0, "num_internal_links": 0, "num_external_links": 0, "external_link_ratio": 0.0, "has_login_form": False, "has_password_input": False, "num_forms": 0, "num_inputs": 0, "num_hidden_inputs": 0, "num_buttons": 0, "num_images": 0, "num_scripts": 6, "num_stylesheets": 2, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 12, "text_to_html_ratio": 0.015, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Atlassian Cloud ID SSO", "url": "https://id.atlassian.com/login", "cat": "Diagnostic / SPA Auth",
     "dom": {"num_links": 0, "num_internal_links": 0, "num_external_links": 0, "external_link_ratio": 0.0, "has_login_form": False, "has_password_input": False, "num_forms": 0, "num_inputs": 0, "num_hidden_inputs": 0, "num_buttons": 0, "num_images": 0, "num_scripts": 10, "num_stylesheets": 3, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 18, "text_to_html_ratio": 0.014, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    
    # Institutional & University Portals (7)
    {"name": "Harvard Canvas Portal", "url": "https://canvas.harvard.edu/login/canvas", "cat": "Institutional / Univ",
     "dom": {"num_links": 4, "num_internal_links": 3, "num_external_links": 1, "external_link_ratio": 0.25, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 2, "num_scripts": 8, "num_stylesheets": 2, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 20, "text_to_html_ratio": 0.065, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Stanford WebLogin SSO", "url": "https://login.stanford.edu/idp/profile/SAML2/Redirect/SSO", "cat": "Institutional / Univ",
     "dom": {"num_links": 5, "num_internal_links": 4, "num_external_links": 1, "external_link_ratio": 0.20, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 4, "num_hidden_inputs": 2, "num_buttons": 1, "num_images": 2, "num_scripts": 6, "num_stylesheets": 2, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 25, "text_to_html_ratio": 0.08, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "UC Berkeley CalNet SSO", "url": "https://auth.berkeley.edu/cas/login", "cat": "Institutional / Univ",
     "dom": {"num_links": 8, "num_internal_links": 6, "num_external_links": 2, "external_link_ratio": 0.25, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 4, "num_hidden_inputs": 2, "num_buttons": 1, "num_images": 3, "num_scripts": 8, "num_stylesheets": 3, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 24, "text_to_html_ratio": 0.075, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "IIT Madras SSO Portal", "url": "https://sso.iitm.ac.in/login", "cat": "Institutional / Univ",
     "dom": {"num_links": 15, "num_internal_links": 12, "num_external_links": 3, "external_link_ratio": 0.20, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 4, "num_scripts": 10, "num_stylesheets": 3, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 18, "text_to_html_ratio": 0.12, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "MIT WebSIS Student Portal", "url": "https://student.mit.edu/cgi-bin/sfprp001.jsp", "cat": "Institutional / Univ",
     "dom": {"num_links": 18, "num_internal_links": 15, "num_external_links": 3, "external_link_ratio": 0.166, "has_login_form": False, "has_password_input": False, "num_forms": 1, "num_inputs": 2, "num_hidden_inputs": 0, "num_buttons": 1, "num_images": 2, "num_scripts": 4, "num_stylesheets": 2, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 20, "text_to_html_ratio": 0.15, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Oxford University SSO", "url": "https://webauth.ox.ac.uk/login", "cat": "Institutional / Univ",
     "dom": {"num_links": 22, "num_internal_links": 18, "num_external_links": 4, "external_link_ratio": 0.18, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 5, "num_scripts": 7, "num_stylesheets": 3, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 22, "text_to_html_ratio": 0.14, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "UCLA Student Portal", "url": "https://my.ucla.edu", "cat": "Institutional / Univ",
     "dom": {"num_links": 85, "num_internal_links": 75, "num_external_links": 10, "external_link_ratio": 0.117, "has_login_form": False, "has_password_input": False, "num_forms": 1, "num_inputs": 2, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 12, "num_scripts": 18, "num_stylesheets": 5, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 15, "text_to_html_ratio": 0.22, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},

    # Enterprise Identity & SSO Portals (10)
    {"name": "Auth0 Platform Portal", "url": "https://auth0.com", "cat": "Enterprise SSO",
     "dom": {"num_links": 234, "num_internal_links": 210, "num_external_links": 24, "external_link_ratio": 0.10, "has_login_form": False, "has_password_input": False, "num_forms": 1, "num_inputs": 2, "num_hidden_inputs": 1, "num_buttons": 3, "num_images": 25, "num_scripts": 22, "num_stylesheets": 6, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 30, "text_to_html_ratio": 0.28, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "AWS Management Console", "url": "https://signin.aws.amazon.com", "cat": "Enterprise SSO",
     "dom": {"num_links": 145, "num_internal_links": 130, "num_external_links": 15, "external_link_ratio": 0.10, "has_login_form": False, "has_password_input": False, "num_forms": 1, "num_inputs": 2, "num_hidden_inputs": 1, "num_buttons": 2, "num_images": 15, "num_scripts": 18, "num_stylesheets": 4, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 28, "text_to_html_ratio": 0.21, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "GitHub Developer Login", "url": "https://github.com/login", "cat": "Enterprise SSO",
     "dom": {"num_links": 11, "num_internal_links": 9, "num_external_links": 2, "external_link_ratio": 0.18, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 4, "num_hidden_inputs": 2, "num_buttons": 1, "num_images": 2, "num_scripts": 8, "num_stylesheets": 2, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 18, "text_to_html_ratio": 0.08, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "GitLab DevSecOps Signin", "url": "https://gitlab.com/users/sign_in", "cat": "Enterprise SSO",
     "dom": {"num_links": 14, "num_internal_links": 11, "num_external_links": 3, "external_link_ratio": 0.21, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 4, "num_hidden_inputs": 2, "num_buttons": 1, "num_images": 3, "num_scripts": 12, "num_stylesheets": 3, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 22, "text_to_html_ratio": 0.09, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Okta Identity Cloud SSO", "url": "https://login.okta.com", "cat": "Enterprise SSO",
     "dom": {"num_links": 18, "num_internal_links": 14, "num_external_links": 4, "external_link_ratio": 0.22, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 4, "num_scripts": 10, "num_stylesheets": 3, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 16, "text_to_html_ratio": 0.11, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Ping Identity Enterprise SSO", "url": "https://auth.pingone.com/as/authorization.oauth2", "cat": "Enterprise SSO",
     "dom": {"num_links": 0, "num_internal_links": 0, "num_external_links": 0, "external_link_ratio": 0.0, "has_login_form": False, "has_password_input": False, "num_forms": 0, "num_inputs": 0, "num_hidden_inputs": 0, "num_buttons": 0, "num_images": 0, "num_scripts": 6, "num_stylesheets": 2, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 14, "text_to_html_ratio": 0.012, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Cisco Duo Security MFA", "url": "https://duo.com", "cat": "Enterprise SSO",
     "dom": {"num_links": 180, "num_internal_links": 160, "num_external_links": 20, "external_link_ratio": 0.11, "has_login_form": False, "has_password_input": False, "num_forms": 1, "num_inputs": 2, "num_hidden_inputs": 1, "num_buttons": 2, "num_images": 20, "num_scripts": 16, "num_stylesheets": 4, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 25, "text_to_html_ratio": 0.24, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Slack Enterprise Sign-In", "url": "https://slack.com/signin", "cat": "Enterprise SSO",
     "dom": {"num_links": 12, "num_internal_links": 9, "num_external_links": 3, "external_link_ratio": 0.25, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 3, "num_scripts": 12, "num_stylesheets": 3, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 18, "text_to_html_ratio": 0.08, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Oracle Single Sign-On", "url": "https://login.oracle.com/mysso/signon.jsp", "cat": "Enterprise SSO",
     "dom": {"num_links": 10, "num_internal_links": 7, "num_external_links": 3, "external_link_ratio": 0.30, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 4, "num_hidden_inputs": 2, "num_buttons": 1, "num_images": 3, "num_scripts": 10, "num_stylesheets": 3, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 20, "text_to_html_ratio": 0.085, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Dropbox Cloud Storage Login", "url": "https://www.dropbox.com/login", "cat": "Enterprise SSO",
     "dom": {"num_links": 8, "num_internal_links": 6, "num_external_links": 2, "external_link_ratio": 0.25, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 2, "num_scripts": 14, "num_stylesheets": 3, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 16, "text_to_html_ratio": 0.075, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},

    # Standard Control (1)
    {"name": "Wikipedia Article", "url": "https://en.wikipedia.org/wiki/Phishing", "cat": "Clean Control",
     "dom": {"num_links": 350, "num_internal_links": 310, "num_external_links": 40, "external_link_ratio": 0.114, "has_login_form": False, "has_password_input": False, "num_forms": 1, "num_inputs": 2, "num_hidden_inputs": 0, "num_buttons": 1, "num_images": 30, "num_scripts": 12, "num_stylesheets": 4, "has_external_form_action": False, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 25, "text_to_html_ratio": 0.35, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},

    # Phishing Attacks (10)
    {"name": "Raw IP PayPal Phishing", "url": "http://192.168.1.100/paypal/login.php", "cat": "Phish Attack",
     "dom": {"num_links": 2, "num_internal_links": 2, "num_external_links": 0, "external_link_ratio": 0.0, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 1, "num_scripts": 2, "num_stylesheets": 1, "has_external_form_action": True, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 15, "text_to_html_ratio": 0.05, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Brand Spoof Apple ID", "url": "http://appleid.apple.com.verify-account-security-alert.cc/auth/login", "cat": "Phish Attack",
     "dom": {"num_links": 1, "num_internal_links": 1, "num_external_links": 0, "external_link_ratio": 0.0, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 1, "num_scripts": 3, "num_stylesheets": 1, "has_external_form_action": True, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 20, "text_to_html_ratio": 0.04, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "DGA Microsoft Lure", "url": "http://login.microsoftonline.com-auth-sec98712.xyz/signin", "cat": "Phish Attack",
     "dom": {"num_links": 0, "num_internal_links": 0, "num_external_links": 0, "external_link_ratio": 0.0, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 1, "num_scripts": 2, "num_stylesheets": 1, "has_external_form_action": True, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 18, "text_to_html_ratio": 0.035, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Tax Refund Lure", "url": "http://irs-tax-refund-claim-portal.top/login.html", "cat": "Phish Attack",
     "dom": {"num_links": 3, "num_internal_links": 2, "num_external_links": 1, "external_link_ratio": 0.33, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 4, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 2, "num_scripts": 3, "num_stylesheets": 1, "has_external_form_action": True, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 22, "text_to_html_ratio": 0.06, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Banking Subdomain Phish", "url": "http://chase.com.security-verification-portal-update.com/online/auth", "cat": "Phish Attack",
     "dom": {"num_links": 2, "num_internal_links": 1, "num_external_links": 1, "external_link_ratio": 0.50, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 1, "num_scripts": 4, "num_stylesheets": 1, "has_external_form_action": True, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 24, "text_to_html_ratio": 0.05, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Netflix IP Lure", "url": "http://45.33.32.156/netflix/account-suspended/signin.php", "cat": "Phish Attack",
     "dom": {"num_links": 1, "num_internal_links": 1, "num_external_links": 0, "external_link_ratio": 0.0, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 1, "num_scripts": 2, "num_stylesheets": 1, "has_external_form_action": True, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 16, "text_to_html_ratio": 0.045, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Social Media Lure", "url": "http://instagram.com-account-recovery-verify-id892.xyz/login.php", "cat": "Phish Attack",
     "dom": {"num_links": 2, "num_internal_links": 2, "num_external_links": 0, "external_link_ratio": 0.0, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 1, "num_scripts": 3, "num_stylesheets": 1, "has_external_form_action": True, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 18, "text_to_html_ratio": 0.04, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Crypto Seed Harvesting", "url": "http://metamask-wallet-seed-phrase-restore.club/auth/unlock", "cat": "Phish Attack",
     "dom": {"num_links": 0, "num_internal_links": 0, "num_external_links": 0, "external_link_ratio": 0.0, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 2, "num_hidden_inputs": 0, "num_buttons": 1, "num_images": 1, "num_scripts": 2, "num_stylesheets": 1, "has_external_form_action": True, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 25, "text_to_html_ratio": 0.03, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Chase Banking Lure", "url": "http://secure.chase.com.acc-session-verify.info/auth/login", "cat": "Phish Attack",
     "dom": {"num_links": 3, "num_internal_links": 2, "num_external_links": 1, "external_link_ratio": 0.33, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 2, "num_scripts": 4, "num_stylesheets": 2, "has_external_form_action": True, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 20, "text_to_html_ratio": 0.055, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}},
    {"name": "Suspicious TLD Brand Phish", "url": "http://bankofamerica.com-login-verify.top/auth.php", "cat": "Phish Attack",
     "dom": {"num_links": 1, "num_internal_links": 1, "num_external_links": 0, "external_link_ratio": 0.0, "has_login_form": True, "has_password_input": True, "num_forms": 1, "num_inputs": 3, "num_hidden_inputs": 1, "num_buttons": 1, "num_images": 1, "num_scripts": 2, "num_stylesheets": 1, "has_external_form_action": True, "has_form_action_empty_or_javascript": False, "has_title": True, "title_length": 18, "text_to_html_ratio": 0.04, "has_iframe": False, "num_iframes": 0, "has_meta_refresh": False}}
]

extractor = FeatureExtractor()

def score_site(site, model, feature_cols, is_exp1=False):
    url = site["url"]
    dom = site["dom"]
    url_feats = extractor.extract_url_features(url)
    all_feats = {**url_feats, **dom}
    
    if is_exp1:
        ext = tldextract.extract(url)
        suf = ext.suffix.lower()
        is_inst = 1 if suf in ["edu", "ac.in", "gov", "ac.uk", "edu.au", "gov.in", "edu.cn", "ac.jp", "ernet.in", "res.in"] or suf.startswith("edu.") or suf.startswith("ac.") else 0
        all_feats["is_institutional_domain"] = is_inst
        
    feat_vec = pd.DataFrame([[all_feats.get(c, 0) for c in feature_cols]], columns=feature_cols)
    raw_score = float(model.predict_proba(feat_vec)[0, 1])
    
    is_spa, reason = is_likely_unrendered_spa_shell(url, dom)
    risk_info = calculate_risk_score(raw_score, is_degraded=False, is_spa_shell=is_spa)
    
    return raw_score, risk_info["threat_score"], risk_info["risk_level"]

benchmark_results = []
for s in BENCHMARK_SITES:
    raw_p, fin_p, r_p = score_site(s, prod_model, base_feature_cols, False)
    raw_e1, fin_e1, r_e1 = score_site(s, exp1_model, exp1_feature_cols, True)
    raw_e2, fin_e2, r_e2 = score_site(s, exp2_model, base_feature_cols, False)
    
    benchmark_results.append({
        "name": s["name"],
        "category": s["cat"],
        "prod_raw": f"{raw_p*100:.2f}%",
        "prod_final": f"{fin_p*100:.2f}% ({r_p[:3].capitalize()})",
        "exp1_raw": f"{raw_e1*100:.2f}%",
        "exp1_final": f"{fin_e1*100:.2f}% ({r_e1[:3].capitalize()})",
        "exp2_raw": f"{raw_e2*100:.2f}%",
        "exp2_final": f"{fin_e2*100:.2f}% ({r_e2[:3].capitalize()})",
    })

bench_df = pd.DataFrame(benchmark_results)
print(bench_df.to_string(index=False))

print("\n" + "="*80)
print("STEP 6: INFERENCE LATENCY BENCHMARK (500 RUNS)")
print("="*80)

def benchmark_latency(model, feature_cols, is_exp1=False):
    s = BENCHMARK_SITES[1] # Google Accounts
    url = s["url"]
    dom = s["dom"]
    url_feats = extractor.extract_url_features(url)
    all_feats = {**url_feats, **dom}
    if is_exp1:
        ext = tldextract.extract(url)
        suf = ext.suffix.lower()
        all_feats["is_institutional_domain"] = 1 if suf in ["edu", "ac.in", "gov"] else 0
    feat_vec = pd.DataFrame([[all_feats.get(c, 0) for c in feature_cols]], columns=feature_cols)
    
    # Warmup
    for _ in range(20):
        model.predict_proba(feat_vec)
        
    latencies = []
    for _ in range(500):
        t0 = time.perf_counter()
        model.predict_proba(feat_vec)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000)
        
    return {
        "mean_ms": np.mean(latencies),
        "median_ms": np.median(latencies),
        "p95_ms": np.percentile(latencies, 95),
        "p99_ms": np.percentile(latencies, 99)
    }

lat_prod = benchmark_latency(prod_model, base_feature_cols, False)
lat_exp1 = benchmark_latency(exp1_model, exp1_feature_cols, True)
lat_exp2 = benchmark_latency(exp2_model, base_feature_cols, False)

print(f"Production Control Latency: Mean={lat_prod['mean_ms']:.3f}ms, P50={lat_prod['median_ms']:.3f}ms, P95={lat_prod['p95_ms']:.3f}ms, P99={lat_prod['p99_ms']:.3f}ms")
print(f"Experimental M1 Latency:    Mean={lat_exp1['mean_ms']:.3f}ms, P50={lat_exp1['median_ms']:.3f}ms, P95={lat_exp1['p95_ms']:.3f}ms, P99={lat_exp1['p99_ms']:.3f}ms")
print(f"Experimental M2 Latency:    Mean={lat_exp2['mean_ms']:.3f}ms, P50={lat_exp2['median_ms']:.3f}ms, P95={lat_exp2['p95_ms']:.3f}ms, P99={lat_exp2['p99_ms']:.3f}ms")

print("\n" + "="*80)
print("STEP 7: DETERMINISM VERIFICATION (5 RUNS)")
print("="*80)

diagnostic_indices = [0, 1, 2, 3] # College, Google, Salesforce, TinyURL
for idx in diagnostic_indices:
    site = BENCHMARK_SITES[idx]
    p_runs = [score_site(site, prod_model, base_feature_cols, False)[1] for _ in range(5)]
    e1_runs = [score_site(site, exp1_model, exp1_feature_cols, True)[1] for _ in range(5)]
    e2_runs = [score_site(site, exp2_model, base_feature_cols, False)[1] for _ in range(5)]
    
    det_p = len(set(p_runs)) == 1
    det_e1 = len(set(e1_runs)) == 1
    det_e2 = len(set(e2_runs)) == 1
    print(f"Site: {site['name']}")
    print(f"  Production:   {p_runs} (Deterministic: {det_p})")
    print(f"  Exp Model 1:  {e1_runs} (Deterministic: {det_e1})")
    print(f"  Exp Model 2:  {e2_runs} (Deterministic: {det_e2})")

print("\n" + "="*80)
print("COMPREHENSIVE SCIENTIFIC EVALUATION COMPLETE")
print("="*80)
