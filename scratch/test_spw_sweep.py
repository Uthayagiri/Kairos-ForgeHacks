from pathlib import Path
import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import GroupKFold

df = pd.read_csv("backend/data/processed/training_dataset_expanded.csv")
df["label_binary"] = df["label"].map({"phishing": 1, "legitimate": 0, 1: 1, 0: 0}).astype(int)
df["registered_domain"] = df["url"].apply(lambda u: ".".join((u.split("://")[-1].split("/")[0]).split(".")[-2:]))

# Normalized features
df["internal_link_ratio"] = np.where(df["num_links"] > 0, np.clip(df["num_internal_links"] / np.maximum(1.0, df["num_links"].astype(float)), 0.0, 1.0), 0.0)
df["external_link_ratio"] = np.clip(df["external_link_ratio"].fillna(0.0).astype(float), 0.0, 1.0)
df["links_per_form"] = np.where(df["num_forms"] > 0, np.clip(df["num_links"].astype(float) / df["num_forms"].astype(float), 0.0, 100.0), 0.0)
df["links_per_input_field"] = np.where(df["num_input_fields"] > 0, np.clip(df["num_links"].astype(float) / df["num_input_fields"].astype(float), 0.0, 100.0), 0.0)
df["subdomain_to_apex_length_ratio"] = 0.0

with open("backend/ml/models/feature_columns.json") as f:
    import json
    prod_cols = json.load(f)

c_cols = [c for c in prod_cols if c != "num_internal_links"] + ["internal_link_ratio", "links_per_form", "links_per_input_field", "subdomain_to_apex_length_ratio"]

gkf = GroupKFold(n_splits=5)
train_idx, test_idx = next(gkf.split(df, df["label_binary"], groups=df["registered_domain"]))

train_df = df.iloc[train_idx]
test_df = df.iloc[test_idx]

X_tr = train_df[c_cols].values
y_tr = train_df["label_binary"].values
X_te = test_df[c_cols].values
y_te = test_df["label_binary"].values

for spw in [5.0, 6.0, 7.0, 8.0, 10.0]:
    clf = xgb.XGBClassifier(
        max_depth=4,
        learning_rate=0.05,
        n_estimators=220,
        colsample_bytree=0.70,
        subsample=0.95,
        reg_lambda=1.0,
        scale_pos_weight=spw,
        random_state=42,
        eval_metric="logloss"
    )
    clf.fit(X_tr, y_tr)
    probs = clf.predict_proba(X_te)[:, 1]
    preds = (probs >= 0.5).astype(int)
    
    rec = recall_score(y_te, preds)
    prec = precision_score(y_te, preds)
    acc = accuracy_score(y_te, preds)
    f1 = f1_score(y_te, preds)
    
    # Sparse legitimate FPR
    sparse_legit = (test_df["label_binary"] == 0) & (test_df["num_links"] <= 20) & (test_df["has_login_form"] == 0)
    sparse_fpr = (preds[sparse_legit] == 1).mean() if sparse_legit.sum() > 0 else 0
    
    print(f"spw={spw:.1f} -> Rec: {rec*100:.2f}%, Prec: {prec*100:.2f}%, Acc: {acc*100:.2f}%, F1: {f1*100:.2f}%, Sparse FPR: {sparse_fpr*100:.2f}%")
