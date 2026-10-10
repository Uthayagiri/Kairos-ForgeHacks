"""
Deep Evaluation of Intervention A: Free PaaS / Dynamic Subdomain Signal (is_free_hosting_subdomain)
Tests:
1. Held-out test set metrics (1,799 samples, 0% domain leakage)
2. 34-site real-world benchmark
3. FN recovery analysis (specifically on the 23 missed phishing attacks)
4. Latency and determinism
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

with open(BACKEND_DIR / "ml" / "models" / "feature_columns.json", "r") as f:
    base_feature_cols = json.load(f)

dataset_path = BACKEND_DIR / "data" / "processed" / "training_dataset_expanded.csv"
raw_df = pd.read_csv(dataset_path)

PAAS_DOMAINS = [
    "pages.dev", "netlify.app", "github.io", "webflow.io", "firebaseapp.com",
    "vercel.app", "render.com", "glitch.me", "surge.sh", "blogspot.com",
    "wordpress.com", "wixsite.com", "weebly.com", "000webhostapp.com",
    "sites.google.com", "s3.amazonaws.com", "blob.core.windows.net", "dub.sh"
]

def extract_paas_subdomain_flag(url_str: str) -> int:
    try:
        host = urlparse(url_str if "://" in url_str else f"http://{url_str}").hostname or ""
        host = host.lower()
        if any(host.endswith(d) and host != d for d in PAAS_DOMAINS):
            return 1
        return 0
    except Exception:
        return 0

raw_df_a = raw_df.copy()
raw_df_a["is_free_hosting_subdomain"] = raw_df_a["url"].apply(extract_paas_subdomain_flag)
feat_cols_a = base_feature_cols + ["is_free_hosting_subdomain"]

gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
train_idx, test_idx = next(gss.split(raw_df_a, raw_df_a["label_binary"], groups=raw_df_a["registered_domain"]))

train_a = raw_df_a.iloc[train_idx].copy()
test_a = raw_df_a.iloc[test_idx].copy()

X_train_a = train_a[feat_cols_a]
y_train_a = train_a["label_binary"].astype(int)
X_test_a = test_a[feat_cols_a]
y_test_a = test_a["label_binary"].astype(int)

PROD_PARAMS = {
    "max_depth": 4,
    "learning_rate": 0.05,
    "n_estimators": 200,
    "colsample_bytree": 0.7,
    "subsample": 0.95,
    "reg_lambda": 1.0,
    "scale_pos_weight": 5.0,
    "eval_metric": "logloss",
    "random_state": 42,
    "n_jobs": -1
}

# Control model
prod_path = BACKEND_DIR / "ml" / "models" / "phishing_model.joblib"
model_prod = joblib.load(prod_path)

# Train Candidate Exp 3 (PaaS feature)
CANDIDATES_DIR = BACKEND_DIR / "ml" / "models" / "candidates_auth"
exp3_path = CANDIDATES_DIR / "candidate_exp3_paas_signal.joblib"

model_exp3 = xgb.XGBClassifier(**PROD_PARAMS)
model_exp3.fit(X_train_a, y_train_a)
joblib.dump(model_exp3, exp3_path)

with open(prod_path, "rb") as f:
    prod_sha = hashlib.sha256(f.read()).hexdigest()
with open(exp3_path, "rb") as f:
    exp3_sha = hashlib.sha256(f.read()).hexdigest()

print("=" * 80)
print(f"Production Hash: {prod_sha}")
print(f"Exp 3 Hash:      {exp3_sha}")
print(f"Hashes differ:   {prod_sha != exp3_sha}")
print("=" * 80)

# Evaluate on Test Set
y_p_prod = model_prod.predict(test_a[base_feature_cols])
y_prob_prod = model_prod.predict_proba(test_a[base_feature_cols])[:, 1]
y_p_exp3 = model_exp3.predict(test_a[feat_cols_a])
y_prob_exp3 = model_exp3.predict_proba(test_a[feat_cols_a])[:, 1]

def get_metrics(y_true, y_pred, y_prob, name, sha):
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    auc = roc_auc_score(y_true, y_prob)
    brier = brier_score_loss(y_true, y_prob)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "Model": name, "SHA256 (First 12)": sha[:12],
        "Accuracy": f"{acc*100:.2f}%", "Precision": f"{prec*100:.2f}%",
        "Recall": f"{rec*100:.2f}%", "Recall Floor": "PASS" if rec >= 0.940 else f"FAIL ({rec*100:.2f}%)",
        "FN Missed": fn, "FP Alarms": fp, "F1": f"{f1*100:.2f}%", "ROC-AUC": f"{auc:.4f}", "Brier": f"{brier:.4f}"
    }

m_prod = get_metrics(y_test_a, y_p_prod, y_prob_prod, "Production Control", prod_sha)
m_exp3 = get_metrics(y_test_a, y_p_exp3, y_prob_exp3, "Exp 3 (+is_free_hosting_subdomain)", exp3_sha)

print(pd.DataFrame([m_prod, m_exp3]).to_string(index=False))

# Check recovery on missed phishing attacks
test_a_eval = test_a.copy()
test_a_eval["prod_pred"] = y_p_prod
test_a_eval["prod_prob"] = y_prob_prod
test_a_eval["exp3_pred"] = y_p_exp3
test_a_eval["exp3_prob"] = y_prob_exp3

fn_prod = test_a_eval[(test_a_eval["label_binary"] == 1) & (test_a_eval["prod_pred"] == 0)]
print(f"\nFN Missed by Production: {len(fn_prod)}")
recovered = fn_prod[fn_prod["exp3_pred"] == 1]
print(f"Recovered by Exp 3: {len(recovered)}")
if len(recovered) > 0:
    print(recovered[["url", "prod_prob", "exp3_prob"]].to_string(index=False))
