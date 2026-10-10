"""Training, Evaluation, and Calibration Pipeline for PhishGuard AI v2.2.0 Candidate Models.

Builds on the clean domain-grouped leakage-free dataset (8,910 samples).
Evaluates multiple regularized architectures and calibration strategies to balance:
  1. High overall phishing recall (>= 94.0%).
  2. Zero recall regression on critical subclasses (shortener phishing, sparse/SPA phishing).
  3. De-concentrated feature importances.
  4. Proper probability calibration (minimizing Brier score and removing artificial 0.4-0.6 clustering).
"""

import datetime
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold
import xgboost as xgb

# Directories
BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_v2_2")

from ml.feature_extraction.url_feature_config import FEATURE_NAMES as URL_FEATURE_NAMES
from ml.feature_extraction.html_feature_config import FEATURE_NAMES as HTML_FEATURE_NAMES


DATA_PATH = BASE_DIR / "data" / "processed" / "training_dataset.csv"
MODELS_DIR = BASE_DIR / "ml" / "models"
CANDIDATES_DIR = BASE_DIR / "ml" / "models" / "candidates_v2_2"
CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)

ORDERED_COLUMNS: List[str] = [
    col if col != "parse_error" else "url_parse_error" for col in URL_FEATURE_NAMES
] + [
    col if col != "parse_error" else "html_parse_error" for col in HTML_FEATURE_NAMES
]


def extract_registered_domain(url_str: str) -> str:
    """Extract registered domain name for leak-free group splitting."""
    try:
        if not isinstance(url_str, str) or not url_str.strip():
            return "unknown"
        target = url_str if "://" in url_str else f"http://{url_str}"
        import urllib.parse
        host = urllib.parse.urlsplit(target).hostname or "unknown"
        host = host.lower().strip(".")
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return "unknown"


def load_and_split_data() -> Tuple[pd.DataFrame, pd.DataFrame, List[str]]:
    """Load dataset and generate deterministic domain-grouped train/test split."""
    df = pd.read_csv(DATA_PATH)
    df["label"] = df["label"].map({"legitimate": 0, "phishing": 1, 0: 0, 1: 1})
    df = df.dropna(subset=["label"]).copy()
    df["label"] = df["label"].astype(int)

    # Ensure all ordered feature columns exist
    for col in ORDERED_COLUMNS:
        if col not in df.columns:
            df[col] = 0

    df["reg_domain"] = df["url"].apply(extract_registered_domain)

    # GroupKFold split (5 folds -> 80% train, 20% test, 0% domain overlap)
    gkf = GroupKFold(n_splits=5)
    train_idx, test_idx = next(gkf.split(df, df["label"], groups=df["reg_domain"]))

    train_df = df.iloc[train_idx].copy()
    test_df = df.iloc[test_idx].copy()

    logger.info("Dataset loaded: %d total samples (%d train, %d test)", len(df), len(train_df), len(test_df))
    logger.info("Train domains: %d, Test domains: %d, Overlap: 0", train_df["reg_domain"].nunique(), test_df["reg_domain"].nunique())
    return train_df, test_df, ORDERED_COLUMNS


def evaluate_model(
    model: Any,
    X_test: np.ndarray,
    y_test: np.ndarray,
    test_df: pd.DataFrame,
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """Compute comprehensive performance metrics, calibration, and subclass recalls."""
    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X_test)[:, 1]
    else:
        y_prob = model.predict(xgb.DMatrix(X_test))

    y_pred = (y_prob >= threshold).astype(int)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_prob))
    brier = float(brier_score_loss(y_test, y_prob))
    cm = confusion_matrix(y_test, y_pred).tolist()

    # Subclass Recalls
    # 1. Shortener phishing recall
    shortener_mask = (test_df["label"] == 1) & (test_df["is_shortened_url"] == 1)
    shortener_rec = float(recall_score(y_test[shortener_mask], y_pred[shortener_mask], zero_division=0)) if shortener_mask.sum() > 0 else 1.0

    # 2. Sparse / Low link phishing recall (num_links <= 20)
    sparse_mask = (test_df["label"] == 1) & (test_df["num_links"] <= 20)
    sparse_rec = float(recall_score(y_test[sparse_mask], y_pred[sparse_mask], zero_division=0)) if sparse_mask.sum() > 0 else 1.0

    # 3. HTTPS phishing recall
    https_mask = (test_df["label"] == 1) & (test_df["uses_https"] == 1)
    https_rec = float(recall_score(y_test[https_mask], y_pred[https_mask], zero_division=0)) if https_mask.sum() > 0 else 1.0

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "brier_score": round(brier, 4),
        "confusion_matrix": {
            "true_negatives": cm[0][0],
            "false_positives": cm[0][1],
            "false_negatives": cm[1][0],
            "true_positives": cm[1][1],
        },
        "subclass_recalls": {
            "shortener_phishing_recall": round(shortener_rec, 4),
            "sparse_phishing_recall": round(sparse_rec, 4),
            "https_phishing_recall": round(https_rec, 4),
        },
    }


def train_candidates() -> Dict[str, Any]:
    """Train and compare regularized and calibrated v2.2.0 candidates."""
    train_df, test_df, feature_cols = load_and_split_data()

    X_train = train_df[feature_cols].values
    y_train = train_df["label"].values
    X_test = test_df[feature_cols].values
    y_test = test_df["label"].values

    candidates_config = [
        # Candidate C1: Regularized depth 4, colsample 0.65, scale_pos_weight 4.0
        {
            "name": "C1_XGB_d4_col0.65_spw4.0",
            "params": {
                "max_depth": 4,
                "learning_rate": 0.05,
                "n_estimators": 220,
                "colsample_bytree": 0.65,
                "subsample": 0.90,
                "reg_lambda": 2.0,
                "scale_pos_weight": 4.0,
                "random_state": 42,
                "eval_metric": "logloss",
            },
            "calibrate": False,
        },
        # Candidate C2: Regularized depth 4, colsample 0.60, scale_pos_weight 3.5 + Calibrated Sigmoid CV
        {
            "name": "C2_Calibrated_d4_col0.60_spw3.5",
            "params": {
                "max_depth": 4,
                "learning_rate": 0.05,
                "n_estimators": 200,
                "colsample_bytree": 0.60,
                "subsample": 0.90,
                "reg_lambda": 2.5,
                "scale_pos_weight": 3.5,
                "random_state": 42,
                "eval_metric": "logloss",
            },
            "calibrate": True,
            "calib_method": "sigmoid",
        },
        # Candidate C3: Regularized depth 4, colsample 0.65, scale_pos_weight 4.5
        {
            "name": "C3_XGB_d4_col0.65_spw4.5",
            "params": {
                "max_depth": 4,
                "learning_rate": 0.05,
                "n_estimators": 220,
                "colsample_bytree": 0.65,
                "subsample": 0.90,
                "reg_lambda": 2.0,
                "scale_pos_weight": 4.5,
                "random_state": 42,
                "eval_metric": "logloss",
            },
            "calibrate": False,
        },
        # Candidate C4: Balanced depth 3, colsample 0.60, scale_pos_weight 4.0 + Calibrated Isotonic
        {
            "name": "C4_Calibrated_d3_col0.60_spw4.0",
            "params": {
                "max_depth": 3,
                "learning_rate": 0.05,
                "n_estimators": 200,
                "colsample_bytree": 0.60,
                "subsample": 0.90,
                "reg_lambda": 2.0,
                "scale_pos_weight": 4.0,
                "random_state": 42,
                "eval_metric": "logloss",
            },
            "calibrate": True,
            "calib_method": "isotonic",
        },
    ]

    results = {}

    for cand in candidates_config:
        name = cand["name"]
        logger.info("Training candidate: %s...", name)
        base_clf = xgb.XGBClassifier(**cand["params"])

        if cand.get("calibrate", False):
            # CalibratedClassifierCV with 5-fold CV
            clf = CalibratedClassifierCV(estimator=base_clf, method=cand["calib_method"], cv=5)
            clf.fit(X_train, y_train)
        else:
            clf = base_clf
            clf.fit(X_train, y_train)

        metrics = evaluate_model(clf, X_test, y_test, test_df)
        
        # Save candidate artifact
        artifact_path = CANDIDATES_DIR / f"{name}.joblib"
        joblib.dump(clf, artifact_path)

        # Feature importances if available
        if hasattr(clf, "feature_importances_"):
            importances = dict(zip(feature_cols, clf.feature_importances_.tolist()))
            sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
            top_imp = dict(sorted_imp[:15])
            top2_conc = (sorted_imp[0][1] + sorted_imp[1][1]) * 100
        elif hasattr(clf, "calibrated_classifiers_"):
            # Average base estimators' feature importances
            avg_imp = np.mean([cc.estimator.feature_importances_ for cc in clf.calibrated_classifiers_], axis=0)
            importances = dict(zip(feature_cols, avg_imp.tolist()))
            sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
            top_imp = dict(sorted_imp[:15])
            top2_conc = (sorted_imp[0][1] + sorted_imp[1][1]) * 100
        else:
            top_imp = {}
            top2_conc = 0.0

        metrics["top2_feature_concentration"] = round(top2_conc, 2)
        metrics["top_importances"] = top_imp
        results[name] = metrics

        logger.info(
            "[%s] Acc: %.2f%% | Prec: %.2f%% | Rec: %.2f%% | F1: %.2f%% | AUC: %.4f | Brier: %.4f | Top2: %.2f%%",
            name,
            metrics["accuracy"] * 100,
            metrics["precision"] * 100,
            metrics["recall"] * 100,
            metrics["f1_score"] * 100,
            metrics["roc_auc"],
            metrics["brier_score"],
            metrics["top2_feature_concentration"],
        )
        logger.info("  Subclasses -> Shortener: %.2f%% | Sparse: %.2f%% | HTTPS: %.2f%%",
            metrics["subclass_recalls"]["shortener_phishing_recall"] * 100,
            metrics["subclass_recalls"]["sparse_phishing_recall"] * 100,
            metrics["subclass_recalls"]["https_phishing_recall"] * 100,
        )

    # Save candidate comparison report
    report_path = CANDIDATES_DIR / "candidate_comparison_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    logger.info("Candidate training complete. Report written to %s", report_path)
    return results


if __name__ == "__main__":
    train_candidates()
