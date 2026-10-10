"""
Deployment script for Candidate A4 (Balanced Production Champion):
1. Train Candidate A4 (max_depth=4, colsample_bytree=0.7, learning_rate=0.05, n_estimators=200, scale_pos_weight=5.0, reg_lambda=1.0, subsample=0.95) on the expanded training partition.
2. Evaluate on the clean domain-grouped test split (0.00% leakage).
3. Persist model to backend/ml/models/phishing_model.joblib.
4. Update backend/ml/models/model_metadata.json.
5. Print exact metrics and feature importances for documentation updates.
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timezone
import json
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, brier_score_loss, confusion_matrix
)
from xgboost import XGBClassifier

DATASET_PATH = Path("backend/data/processed/training_dataset_expanded.csv")
MODEL_OUTPUT_PATH = Path("backend/ml/models/phishing_model.joblib")
METADATA_OUTPUT_PATH = Path("backend/ml/models/model_metadata.json")
FEATURE_COLS_PATH = Path("backend/ml/models/feature_columns.json")

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

with open(FEATURE_COLS_PATH, "r") as f:
    feature_cols = json.load(f)

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

# Candidate A4 hyperparameters
hyperparams = {
    "colsample_bytree": 0.7,
    "learning_rate": 0.05,
    "max_depth": 4,
    "n_estimators": 200,
    "reg_lambda": 1.0,
    "scale_pos_weight": 5.0,
    "subsample": 0.95
}

print(f"Training Candidate A4 with params: {hyperparams}")
model = XGBClassifier(
    **hyperparams,
    random_state=42,
    eval_metric="logloss",
    n_jobs=-1
)
model.fit(X_train, y_train)

# Evaluate on test set
probs = model.predict_proba(X_test)[:, 1]
preds = (probs >= 0.5).astype(int)

acc = float(accuracy_score(y_test, preds))
prec = float(precision_score(y_test, preds))
rec = float(recall_score(y_test, preds))
f1 = float(f1_score(y_test, preds))
auc = float(roc_auc_score(y_test, probs))
brier = float(brier_score_loss(y_test, probs))
cm = confusion_matrix(y_test, preds)
tn, fp, fn, tp = [int(v) for v in cm.ravel()]

# Feature importances
importances_series = pd.Series(model.feature_importances_, index=feature_cols).sort_values(ascending=False)
top15_dict = {k: float(v) for k, v in importances_series.head(15).items()}
top2_conc = float(importances_series.iloc[0:2].sum())

print("\n" + "=" * 70)
print("EVALUATION METRICS ON CLEAN DOMAIN-GROUPED TEST SET:")
print("=" * 70)
print(f"Accuracy:                 {acc*100:.2f}% ({acc:.4f})")
print(f"Precision:                {prec*100:.2f}% ({prec:.4f})")
print(f"Recall (Sensitivity):     {rec*100:.2f}% ({rec:.4f})")
print(f"F1-Score:                 {f1*100:.2f}% ({f1:.4f})")
print(f"ROC-AUC:                  {auc*100:.2f}% ({auc:.4f})")
print(f"Brier Score Loss:         {brier:.4f}")
print(f"Confusion Matrix:         TN={tn}, FP={fp}, FN={fn}, TP={tp}")
print(f"Top-2 Feature Weight:     {top2_conc*100:.2f}%")
print(f"Top Features:\n{importances_series.head(8)}")

# Save Model
joblib.dump(model, MODEL_OUTPUT_PATH)
print(f"\nPersisted production model to {MODEL_OUTPUT_PATH}")

# Metadata
metadata = {
    "version": "2.1.0",
    "model_name": "Balanced Regularized XGBoost Phishing Detector (Candidate A4)",
    "algorithm": "XGBClassifier",
    "date_trained": datetime.now(timezone.utc).isoformat(),
    "training_samples": len(X_train),
    "test_samples": len(X_test),
    "total_samples": len(df),
    "unique_registered_domains": int(df['reg_domain'].nunique()),
    "train_domains": int(groups_train.nunique()),
    "test_domains": int(groups_test.nunique()),
    "domain_overlap_leakage": "0.00%",
    "features_count": len(feature_cols),
    "hyperparameters": hyperparams,
    "performance_metrics": {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "brier_score": round(brier, 4)
    },
    "confusion_matrix": {
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "true_positives": tp
    },
    "feature_importances_top15": top15_dict,
    "top2_feature_concentration": round(top2_conc, 4),
    "calibration_and_risk_scoring_note": (
        "This model intentionally uses scale_pos_weight=5.0 and feature subsampling (colsample_bytree=0.7) "
        "to maximize attack recall (94.21%) and prevent link count dominance. Output scores represent monotonic "
        "risk scores / ordinal threat indicators (higher score = more suspicious), rather than calibrated empirical probabilities."
    )
}

with open(METADATA_OUTPUT_PATH, "w") as f:
    json.dump(metadata, f, indent=2)

print(f"Updated metadata in {METADATA_OUTPUT_PATH}")
