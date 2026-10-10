"""Persist the new calibrated production model and generate updated model_metadata.json."""

import datetime
import json
import shutil
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

BACKEND_DIR = Path("backend")
DATASET_PATH = BACKEND_DIR / "data" / "processed" / "training_dataset_expanded.csv"
FEATURE_COLS_PATH = BACKEND_DIR / "ml" / "models" / "feature_columns.json"
MODELS_DIR = BACKEND_DIR / "ml" / "models"
MODEL_FILE_PATH = MODELS_DIR / "phishing_model.joblib"
METADATA_FILE_PATH = MODELS_DIR / "model_metadata.json"

SRC_MODEL_PATH = Path("scratch") / "model_candidates" / "phishing_model_v2_sigmoid.joblib"
SRC_BASE_PATH = Path("scratch") / "model_candidates" / "phishing_model_v2_uncalibrated.joblib"


def persist_production_model():
    print("Persisting production calibrated model artifact...")
    shutil.copy(SRC_MODEL_PATH, MODEL_FILE_PATH)

    # Compute exact evaluation metrics on test set
    df = pd.read_csv(DATASET_PATH)
    feature_cols = json.load(open(FEATURE_COLS_PATH))
    groups = df["registered_domain"]
    X = df[feature_cols]
    y = df["label_binary"]

    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups=groups))

    X_test, y_test = X.iloc[test_idx], y.iloc[test_idx]

    model = joblib.load(MODEL_FILE_PATH)
    base_xgb = joblib.load(SRC_BASE_PATH)

    probs = model.predict_proba(X_test)[:, 1]
    preds = (probs >= 0.5).astype(int)

    acc = round(float(accuracy_score(y_test, preds)), 4)
    prec = round(float(precision_score(y_test, preds)), 4)
    rec = round(float(recall_score(y_test, preds)), 4)
    f1 = round(float(f1_score(y_test, preds)), 4)
    auc = round(float(roc_auc_score(y_test, probs)), 4)
    brier = round(float(brier_score_loss(y_test, probs)), 4)
    cm = confusion_matrix(y_test, preds)

    # Feature importances from base regularized booster
    importances = base_xgb.feature_importances_
    fi = sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)

    metadata = {
        "model_type": "xgboost_calibrated_sigmoid",
        "model_version": "2.0.0",
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dataset_info": {
            "source": "backend/data/processed/training_dataset_expanded.csv (domain-diversified)",
            "total_rows": len(df),
            "num_features": len(feature_cols),
            "unique_domains": int(groups.nunique()),
            "train_samples": len(train_idx),
            "test_samples": len(test_idx),
            "class_distribution": {
                "legitimate_total": int((y == 0).sum()),
                "phishing_total": int((y == 1).sum()),
                "imbalance_ratio": round(float((y == 0).sum() / (y == 1).sum()), 4),
            },
            "train_test_split": {
                "method": "GroupShuffleSplit",
                "test_size": 0.2,
                "random_state": 42,
                "domain_leakage_overlap_pct": 0.0,
            },
        },
        "hyperparameters_base_xgb": {
            "colsample_bytree": 0.6,
            "learning_rate": 0.03,
            "max_depth": 3,
            "min_child_weight": 4,
            "n_estimators": 150,
            "reg_lambda": 1.0,
            "scale_pos_weight": 3.7155,
            "subsample": 0.95,
        },
        "calibration": {
            "method": "sigmoid",
            "cv_folds": 5,
            "brier_score": brier,
        },
        "test_set_evaluation_domain_grouped": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "roc_auc": auc,
            "brier_score": brier,
            "confusion_matrix": {
                "tn": int(cm[0, 0]),
                "fp": int(cm[0, 1]),
                "fn": int(cm[1, 0]),
                "tp": int(cm[1, 1]),
            },
        },
        "top_10_feature_importances": [
            {"feature": name, "importance": round(float(imp), 6)} for name, imp in fi[:10]
        ],
        "feature_count": len(feature_cols),
        "feature_names": feature_cols,
    }

    with open(METADATA_FILE_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"Updated {METADATA_FILE_PATH} successfully.")


if __name__ == "__main__":
    persist_production_model()
