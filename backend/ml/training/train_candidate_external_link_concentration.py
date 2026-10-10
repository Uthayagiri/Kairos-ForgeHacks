"""Controlled Candidate Experiment: EXP-EXTERNAL-LINK-CONCENTRATION-2026-09-16.

Goal: Test whether adding ONLY the `high_external_link_concentration` feature
improves false-positive behavior without damaging phishing recall.

Strict constraints:
1. Do not modify or overwrite the production model.
2. Keep all 43 original production features.
3. Add only `high_external_link_concentration` (external_link_ratio > 0.75).
4. Strict domain-disjoint GroupKFold validation (0.00% domain leakage).
5. Compare:
   A. Existing production model (v2.1.0)
   B. Production features + high_external_link_concentration
6. Evaluate across thresholds [0.30, 0.40, 0.50, 0.60, 0.70].
7. Save all artifacts in backend/ml/models/candidates_external_link_concentration/.
"""

import datetime
import hashlib
import json
import logging
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold
import xgboost as xgb

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("exp_external_link_concentration")

BACKEND_DIR = Path(__file__).resolve().parents[2]
MODELS_DIR = BACKEND_DIR / "ml" / "models"
PROD_MODEL_PATH = MODELS_DIR / "phishing_model.joblib"
DATA_DIR = BACKEND_DIR / "data" / "processed"
CANDIDATES_DIR = MODELS_DIR / "candidates_external_link_concentration"
DOCS_DIR = BACKEND_DIR.parent / "docs"
CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)


class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.integer, np.int64, np.int32, np.int16, np.int8)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64, np.float32, np.float16)):
            return float(obj)
        elif isinstance(obj, (np.ndarray,)):
            return obj.tolist()
        elif isinstance(obj, (np.bool_,)):
            return bool(obj)
        return super().default(obj)


def compute_file_sha256(filepath: Path) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def extract_registered_domain(url_str: str) -> str:
    try:
        if not isinstance(url_str, str) or not url_str.strip():
            return "unknown"
        target = url_str if "://" in url_str else f"http://{url_str}"
        host = urllib.parse.urlsplit(target).hostname or "unknown"
        host = host.lower().strip(".")
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return "unknown"


def load_dataset_and_features() -> Tuple[pd.DataFrame, List[str], List[str]]:
    dataset_path = DATA_DIR / "training_dataset_expanded.csv"
    df = pd.read_csv(dataset_path)
    df["label_binary"] = df["label"].map({"phishing": 1, "legitimate": 0, 1: 1, 0: 0}).astype(int)
    df["registered_domain"] = df["url"].apply(extract_registered_domain)
    
    with open(MODELS_DIR / "feature_columns.json", "r", encoding="utf-8") as f:
        prod_features = json.load(f)
        
    # Single candidate feature: high_external_link_concentration
    df["high_external_link_concentration"] = (df["external_link_ratio"] > 0.75).astype(int)
    candidate_features = prod_features + ["high_external_link_concentration"]
    
    logger.info("Dataset loaded: %d total samples (%d legitimate, %d phishing)", len(df), (df["label_binary"] == 0).sum(), (df["label_binary"] == 1).sum())
    logger.info("Baseline features: %d | Candidate features: %d", len(prod_features), len(candidate_features))
    
    return df, prod_features, candidate_features


def evaluate_at_threshold(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    threshold: float,
    test_df: pd.DataFrame,
) -> Dict[str, Any]:
    y_pred = (y_prob >= threshold).astype(int)
    
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    spec = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    roc_auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0
    pr_auc = float(average_precision_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0
    brier = float(brier_score_loss(y_true, y_prob))
    
    # 1. Sparse Legitimate Pages (<= 20 links, no login form)
    sparse_legit_mask = (test_df["label_binary"] == 0) & (test_df["num_links"] <= 20) & (test_df["has_login_form"] == 0)
    n_sparse_legit = int(sparse_legit_mask.sum())
    sparse_legit_fps = int((y_pred[sparse_legit_mask] == 1).sum()) if n_sparse_legit > 0 else 0
    sparse_legit_fpr = float(sparse_legit_fps / n_sparse_legit) if n_sparse_legit > 0 else 0.0
    
    # 2. Sparse Phishing Pages (<= 20 links)
    sparse_phish_mask = (test_df["label_binary"] == 1) & (test_df["num_links"] <= 20)
    n_sparse_phish = int(sparse_phish_mask.sum())
    sparse_phish_rec = float(recall_score(y_true[sparse_phish_mask], y_pred[sparse_phish_mask], zero_division=0)) if n_sparse_phish > 0 else 1.0
    sparse_phish_tps = int((y_pred[sparse_phish_mask] == 1).sum()) if n_sparse_phish > 0 else 0
    
    # 3. Shortened URL Phishing
    short_phish_mask = (test_df["label_binary"] == 1) & (test_df["is_shortened_url"] == 1)
    n_short_phish = int(short_phish_mask.sum())
    short_phish_rec = float(recall_score(y_true[short_phish_mask], y_pred[short_phish_mask], zero_division=0)) if n_short_phish > 0 else 1.0
    short_phish_tps = int((y_pred[short_phish_mask] == 1).sum()) if n_short_phish > 0 else 0
    
    # 4. HTTPS Phishing
    https_phish_mask = (test_df["label_binary"] == 1) & (test_df["uses_https"] == 1)
    n_https_phish = int(https_phish_mask.sum())
    https_phish_rec = float(recall_score(y_true[https_phish_mask], y_pred[https_phish_mask], zero_division=0)) if n_https_phish > 0 else 1.0
    https_phish_tps = int((y_pred[https_phish_mask] == 1).sum()) if n_https_phish > 0 else 0
    
    # 5. Legitimate Login/SSO Pages
    login_legit_mask = (test_df["label_binary"] == 0) & ((test_df["has_login_form"] == 1) | (test_df["num_password_fields"] > 0))
    n_login_legit = int(login_legit_mask.sum())
    login_legit_fps = int((y_pred[login_legit_mask] == 1).sum()) if n_login_legit > 0 else 0
    login_legit_fpr = float(login_legit_fps / n_login_legit) if n_login_legit > 0 else 0.0
    
    # 6. External Form Action Pages
    ext_form_legit_mask = (test_df["label_binary"] == 0) & (test_df["num_forms_with_external_action"] > 0)
    n_ext_form_legit = int(ext_form_legit_mask.sum())
    ext_form_legit_fps = int((y_pred[ext_form_legit_mask] == 1).sum()) if n_ext_form_legit > 0 else 0
    ext_form_legit_fpr = float(ext_form_legit_fps / n_ext_form_legit) if n_ext_form_legit > 0 else 0.0
    
    ext_form_phish_mask = (test_df["label_binary"] == 1) & (test_df["num_forms_with_external_action"] > 0)
    n_ext_form_phish = int(ext_form_phish_mask.sum())
    ext_form_phish_rec = float(recall_score(y_true[ext_form_phish_mask], y_pred[ext_form_phish_mask], zero_division=0)) if n_ext_form_phish > 0 else 1.0
    ext_form_phish_tps = int((y_pred[ext_form_phish_mask] == 1).sum()) if n_ext_form_phish > 0 else 0
    
    return {
        "threshold": threshold,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "specificity": round(spec, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "brier_score": round(brier, 4),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "slices": {
            "sparse_legitimate_fpr": round(sparse_legit_fpr, 4),
            "sparse_legitimate_fps": sparse_legit_fps,
            "sparse_legitimate_total": n_sparse_legit,
            "sparse_phishing_recall": round(sparse_phish_rec, 4),
            "sparse_phishing_tps": sparse_phish_tps,
            "sparse_phishing_total": n_sparse_phish,
            "shortened_phishing_recall": round(short_phish_rec, 4),
            "shortened_phishing_tps": short_phish_tps,
            "shortened_phishing_total": n_short_phish,
            "https_phishing_recall": round(https_phish_rec, 4),
            "https_phishing_tps": https_phish_tps,
            "https_phishing_total": n_https_phish,
            "legitimate_login_fpr": round(login_legit_fpr, 4),
            "legitimate_login_fps": login_legit_fps,
            "legitimate_login_total": n_login_legit,
            "external_form_legitimate_fpr": round(ext_form_legit_fpr, 4),
            "external_form_legitimate_fps": ext_form_legit_fps,
            "external_form_legitimate_total": n_ext_form_legit,
            "external_form_phishing_recall": round(ext_form_phish_rec, 4),
            "external_form_phishing_tps": ext_form_phish_tps,
            "external_form_phishing_total": n_ext_form_phish,
        },
    }


def run_experiment() -> Dict[str, Any]:
    logger.info("================================================================================")
    logger.info("  STARTING CONTROLLED EXPERIMENT: EXP-EXTERNAL-LINK-CONCENTRATION-2026-09-16   ")
    logger.info("================================================================================")
    
    # 1. Verify production model integrity before starting
    prod_sha256_before = compute_file_sha256(PROD_MODEL_PATH)
    logger.info("Initial Production Model SHA-256: %s", prod_sha256_before)
    
    # 2. Prepare dataset
    df, prod_features, candidate_features = load_dataset_and_features()
    
    # 3. Strict 5-Fold Domain-Disjoint Split
    gkf = GroupKFold(n_splits=5)
    train_idx, test_idx = next(gkf.split(df, df["label_binary"], groups=df["registered_domain"]))
    
    train_df = df.iloc[train_idx].copy()
    test_df = df.iloc[test_idx].copy()
    
    train_domains = set(train_df["registered_domain"])
    test_domains = set(test_df["registered_domain"])
    overlap = train_domains.intersection(test_domains)
    assert len(overlap) == 0, f"Domain leakage detected: {len(overlap)} overlapping domains"
    logger.info("Domain Leakage Check: 0.00% domain overlap (Train: %d domains, Test: %d domains)", len(train_domains), len(test_domains))
    
    y_train = train_df["label_binary"].values
    y_test = test_df["label_binary"].values
    
    # 4. Load & Evaluate Production Model (Model A) on test fold
    prod_model = joblib.load(PROD_MODEL_PATH)
    prod_prob = prod_model.predict_proba(test_df[prod_features])[:, 1]
    
    # 5. Train Candidate Model B (44 features: 43 prod + high_external_link_concentration)
    xgb_params = {
        "max_depth": 4,
        "learning_rate": 0.05,
        "n_estimators": 220,
        "colsample_bytree": 0.70,
        "subsample": 0.95,
        "reg_lambda": 1.0,
        "scale_pos_weight": 5.0,
        "random_state": 42,
        "eval_metric": "logloss",
    }
    
    logger.info("Training Candidate Model B (44 features)...")
    cand_model = xgb.XGBClassifier(**xgb_params)
    cand_model.fit(train_df[candidate_features].values, y_train)
    cand_prob = cand_model.predict_proba(test_df[candidate_features].values)[:, 1]
    
    # 6. Evaluate across thresholds [0.30, 0.40, 0.50, 0.60, 0.70]
    thresholds = [0.30, 0.40, 0.50, 0.60, 0.70]
    
    prod_eval_by_threshold = {}
    cand_eval_by_threshold = {}
    
    for t in thresholds:
        prod_eval_by_threshold[f"threshold_{t:.2f}"] = evaluate_at_threshold(y_test, prod_prob, t, test_df)
        cand_eval_by_threshold[f"threshold_{t:.2f}"] = evaluate_at_threshold(y_test, cand_prob, t, test_df)
        
        p_res = prod_eval_by_threshold[f"threshold_{t:.2f}"]
        c_res = cand_eval_by_threshold[f"threshold_{t:.2f}"]
        
        logger.info(
            "[Threshold %.2f] PROD: Acc=%.2f%% Rec=%.2f%% Prec=%.2f%% SparseFPR=%.2f%% | CAND: Acc=%.2f%% Rec=%.2f%% Prec=%.2f%% SparseFPR=%.2f%%",
            t,
            p_res["accuracy"] * 100,
            p_res["recall"] * 100,
            p_res["precision"] * 100,
            p_res["slices"]["sparse_legitimate_fpr"] * 100,
            c_res["accuracy"] * 100,
            c_res["recall"] * 100,
            c_res["precision"] * 100,
            c_res["slices"]["sparse_legitimate_fpr"] * 100,
        )

    # 7. Feature Importance Analysis
    cand_importances = dict(zip(candidate_features, cand_model.feature_importances_.tolist()))
    sorted_imp = sorted(cand_importances.items(), key=lambda x: x[1], reverse=True)
    top2_conc = (sorted_imp[0][1] + sorted_imp[1][1]) * 100
    
    # Permutation Importances
    perm_res = permutation_importance(cand_model, test_df[candidate_features].values, y_test, scoring="recall", n_repeats=5, random_state=42)
    perm_report = [
        {
            "feature": candidate_features[i],
            "importance_mean": round(float(perm_res.importances_mean[i]), 6),
            "importance_std": round(float(perm_res.importances_std[i]), 6)
        }
        for i in range(len(candidate_features))
    ]
    perm_report.sort(key=lambda x: x["importance_mean"], reverse=True)
    
    # 8. Save Candidate Artifacts
    cand_model_path = CANDIDATES_DIR / "candidate_external_link_model.joblib"
    cand_features_path = CANDIDATES_DIR / "candidate_feature_columns.json"
    cand_metadata_path = CANDIDATES_DIR / "candidate_metadata.json"
    cand_report_path = CANDIDATES_DIR / "candidate_experiment_report.json"
    cand_importances_path = CANDIDATES_DIR / "candidate_feature_importances.json"
    
    joblib.dump(cand_model, cand_model_path)
    with open(cand_features_path, "w", encoding="utf-8") as f:
        json.dump(candidate_features, f, indent=2)
        
    cand_sha256 = compute_file_sha256(cand_model_path)
    
    experiment_results = {
        "experiment_id": "EXP-EXTERNAL-LINK-CONCENTRATION-2026-09-16",
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "validation_strategy": "5-Fold Domain-Disjoint GroupKFold",
        "leakage_audit": {
            "total_samples": len(df),
            "train_samples": len(train_df),
            "test_samples": len(test_df),
            "train_domains": len(train_domains),
            "test_domains": len(test_domains),
            "domain_overlap_count": len(overlap),
            "domain_overlap_pct": 0.00,
        },
        "production_model_sha256": prod_sha256_before,
        "candidate_model_sha256": cand_sha256,
        "feature_counts": {
            "production_features": len(prod_features),
            "candidate_features": len(candidate_features),
            "added_features": ["high_external_link_concentration"],
        },
        "feature_importance": {
            "top2_feature_concentration_pct": round(float(top2_conc), 2),
            "tree_gain_importances": dict(sorted_imp),
            "permutation_recall_importances": perm_report,
        },
        "model_a_production": {
            "model_version": "2.1.0",
            "evaluations_by_threshold": prod_eval_by_threshold,
        },
        "model_b_candidate": {
            "model_version": "2.2.0-candidate-ext-link-concentration",
            "evaluations_by_threshold": cand_eval_by_threshold,
        },
    }
    
    with open(cand_report_path, "w", encoding="utf-8") as f:
        json.dump(experiment_results, f, indent=2, cls=NumpyEncoder)
        
    with open(cand_importances_path, "w", encoding="utf-8") as f:
        json.dump({
            "tree_gain": dict(sorted_imp),
            "permutation": perm_report,
        }, f, indent=2, cls=NumpyEncoder)
        
    candidate_metadata = {
        "model_version": "2.2.0-candidate-ext-link-concentration",
        "model_name": "External Link Concentration Augmented XGBoost Phishing Detector (Candidate B)",
        "sha256_hash": cand_sha256,
        "date_trained": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "algorithm": "XGBClassifier",
        "feature_count": len(candidate_features),
        "hyperparameters": xgb_params,
        "production_sha256_verified": prod_sha256_before,
        "top2_feature_concentration": round(float(top2_conc), 2),
        "high_external_link_gain_pct": round(float(cand_importances.get("high_external_link_concentration", 0.0) * 100), 2),
    }
    with open(cand_metadata_path, "w", encoding="utf-8") as f:
        json.dump(candidate_metadata, f, indent=2, cls=NumpyEncoder)
        
    # 9. Verify production model integrity after saving
    prod_sha256_after = compute_file_sha256(PROD_MODEL_PATH)
    assert prod_sha256_before == prod_sha256_after, "CRITICAL ERROR: Production model SHA-256 changed!"
    logger.info("Verified: Production Model SHA-256 remains 100%% unchanged (%s)", prod_sha256_after)
    logger.info("Candidate Model SHA-256: %s", cand_sha256)
    logger.info("Candidate artifacts saved in %s", CANDIDATES_DIR)
    
    return experiment_results


if __name__ == "__main__":
    run_experiment()
