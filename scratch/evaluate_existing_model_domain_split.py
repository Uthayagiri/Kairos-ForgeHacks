"""Evaluate CURRENT deployed model on strict domain-grouped split.

Isolates the exact metric impact of domain-overlap leakage on the existing model.
"""

import json
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

# Paths
BACKEND_DIR = Path("backend")
DATASET_PATH = BACKEND_DIR / "data" / "processed" / "training_dataset.csv"
MODEL_PATH = BACKEND_DIR / "ml" / "models" / "phishing_model.joblib"
FEATURE_COLS_PATH = BACKEND_DIR / "ml" / "models" / "feature_columns.json"


def extract_registered_domain(url: str) -> str:
    """Extract registered domain (approximate 2-level or 3-level domain)."""
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
        return url


def evaluate():
    df = pd.read_csv(DATASET_PATH)
    df["registered_domain"] = df["url"].apply(extract_registered_domain)
    
    feature_cols = json.load(open(FEATURE_COLS_PATH))
    model = joblib.load(MODEL_PATH)
    
    # Strict domain-grouped 80/20 split
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(df, groups=df["registered_domain"]))
    
    train_df = df.iloc[train_idx]
    test_df = df.iloc[test_idx]
    
    train_doms = set(train_df["registered_domain"])
    test_doms = set(test_df["registered_domain"])
    overlap = test_doms.intersection(train_doms)
    
    print("=" * 80)
    print("STANDALONE BASELINE: CURRENT DEPLOYED MODEL ON DOMAIN-GROUPED SPLIT")
    print("=" * 80)
    print(f"Total dataset: {len(df)} samples, {df['registered_domain'].nunique()} unique domains")
    print(f"Train split:   {len(train_df)} samples, {len(train_doms)} unique domains")
    print(f"Test split:    {len(test_df)} samples, {len(test_doms)} unique domains")
    print(f"Overlap:       {len(overlap)} domains (0.00% verified)\n")
    
    print(f"Test Class Distribution:")
    print(f"  - Legitimate (0): {(test_df['label_binary'] == 0).sum()} ({(test_df['label_binary'] == 0).sum()/len(test_df)*100:.2f}%)")
    print(f"  - Phishing (1):   {(test_df['label_binary'] == 1).sum()} ({(test_df['label_binary'] == 1).sum()/len(test_df)*100:.2f}%)")
    
    X_test = test_df[feature_cols]
    y_test = test_df["label_binary"]
    
    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob >= 0.5).astype(int)
    
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    brier = brier_score_loss(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)
    
    print("\n--- STANDALONE CURRENT MODEL METRICS ON DOMAIN-GROUPED TEST SET ---")
    print(f"Accuracy:        {acc:.4f} ({acc*100:.2f}%)   [vs 0.9688 originally reported]")
    print(f"Precision:       {prec:.4f} ({prec*100:.2f}%)   [vs 0.9188 originally reported]")
    print(f"Recall:          {rec:.4f} ({rec*100:.2f}%)   [vs 0.9687 originally reported]")
    print(f"F1-Score:        {f1:.4f} ({f1*100:.2f}%)   [vs 0.9431 originally reported]")
    print(f"ROC-AUC:         {auc:.4f} ({auc*100:.2f}%)   [vs 0.9955 originally reported]")
    print(f"Brier Score:     {brier:.4f}")
    print(f"\nConfusion Matrix (TN, FP, FN, TP):")
    print(f"  TN = {cm[0, 0]}  (True Negatives: Legitimate correctly classified as Safe)")
    print(f"  FP = {cm[0, 1]}  (False Positives: Legitimate misclassified as Phishing, FP rate: {cm[0,1]/(cm[0,0]+cm[0,1])*100:.2f}%)")
    print(f"  FN = {cm[1, 0]}  (False Negatives: Phishing attacks missed, FN rate: {cm[1,0]/(cm[1,0]+cm[1,1])*100:.2f}%)")
    print(f"  TP = {cm[1, 1]}  (True Positives: Phishing attacks caught)")
    print("=" * 80)


if __name__ == "__main__":
    evaluate()
