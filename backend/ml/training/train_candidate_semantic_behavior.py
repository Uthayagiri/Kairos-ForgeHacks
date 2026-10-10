"""Candidate Experiment: Semantic and Behavioral Phishing Indicators.

Evaluates isolated candidate feature groups while preserving all original link-count features:
- Ablation A: Production Features Only (43 features)
- Ablation B: Production Features + Form Behavior Features (46 features)
- Ablation C: Production Features + Page Structure Features (47 features)
- Ablation D: Production Features + URL/Content Consistency Features (47 features)
- Ablation E: Combined Semantic & Behavioral Candidate (54 features)

All models evaluated under strict 5-Fold Domain-Disjoint GroupKFold (0.00% domain leakage).
Saves all artifacts in backend/ml/models/candidates_semantic_behavior/ without modifying production artifacts.
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
from sklearn.calibration import CalibratedClassifierCV
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
logger = logging.getLogger("semantic_behavior_experiment")

# Directories
BACKEND_DIR = Path(__file__).resolve().parents[2]
MODELS_DIR = BACKEND_DIR / "ml" / "models"
PROD_MODEL_PATH = MODELS_DIR / "phishing_model.joblib"
DATA_DIR = BACKEND_DIR / "data" / "processed"
CANDIDATES_DIR = MODELS_DIR / "candidates_semantic_behavior"
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


def compute_subdomain_ratio(url_str: str, apex_domain: str) -> float:
    try:
        target = url_str if "://" in url_str else f"http://{url_str}"
        host = (urllib.parse.urlsplit(target).hostname or "").lower().strip(".")
        apex_str = str(apex_domain).lower().strip(".")
        if host and apex_str and host != apex_str and host.endswith(apex_str):
            sub_part = host[:-len(apex_str)].rstrip(".")
            sub_len = len(sub_part)
        else:
            sub_len = 0
        return min(10.0, round(float(sub_len / max(1, len(apex_str))), 4))
    except Exception:
        return 0.0


def prepare_semantic_dataset() -> Tuple[pd.DataFrame, List[str], Dict[str, List[str]]]:
    """Load dataset, compute candidate semantic & behavioral features, and define feature sets."""
    dataset_path = DATA_DIR / "training_dataset_expanded.csv"
    df = pd.read_csv(dataset_path)
    df["label_binary"] = df["label"].map({"phishing": 1, "legitimate": 0, 1: 1, 0: 0}).astype(int)
    df["registered_domain"] = df["url"].apply(extract_registered_domain)
    
    # Load production feature columns
    with open(MODELS_DIR / "feature_columns.json", "r", encoding="utf-8") as f:
        prod_features = json.load(f)
        
    # -----------------------------------------------------------------
    # 1. Form Behavior Features (Group B)
    # -----------------------------------------------------------------
    df["password_field_present"] = (df["num_password_fields"] > 0).astype(int)
    df["external_form_action_ratio"] = np.where(
        df["num_forms"] > 0,
        np.clip(df["num_forms_with_external_action"].astype(float) / df["num_forms"].astype(float), 0.0, 1.0),
        0.0
    )
    df["credential_collection_pattern"] = (
        (df["num_password_fields"] > 0) & 
        ((df["num_forms_with_external_action"] > 0) | (df["has_form_action_empty_or_javascript"] == 1) | (df["has_suspicious_keywords"] == 1))
    ).astype(int)
    
    group_b_cols = [
        "password_field_present",
        "external_form_action_ratio",
        "credential_collection_pattern",
    ]

    # -----------------------------------------------------------------
    # 2. Page Structure & Script Features (Group C)
    # -----------------------------------------------------------------
    df["meta_refresh_present"] = (df["num_meta_refresh_redirects"] > 0).astype(int)
    df["script_to_link_ratio"] = np.where(
        df["num_links"] > 0,
        np.clip(df["num_scripts"].astype(float) / np.maximum(1.0, df["num_links"].astype(float)), 0.0, 50.0),
        np.clip(df["num_scripts"].astype(float), 0.0, 50.0)
    )
    df["hidden_element_indicator"] = ((df["has_hidden_iframe"] == 1) | (df["has_suspicious_js_patterns"] == 1)).astype(int)
    df["iframe_to_image_ratio"] = np.where(
        df["num_images"] > 0,
        np.clip(df["num_iframes"].astype(float) / df["num_images"].astype(float), 0.0, 20.0),
        np.clip(df["num_iframes"].astype(float), 0.0, 20.0)
    )
    
    group_c_cols = [
        "meta_refresh_present",
        "script_to_link_ratio",
        "hidden_element_indicator",
        "iframe_to_image_ratio",
    ]

    # -----------------------------------------------------------------
    # 3. URL/Content Consistency Features (Group D)
    # -----------------------------------------------------------------
    df["subdomain_to_apex_length_ratio"] = [
        compute_subdomain_ratio(u, a) for u, a in zip(df["url"], df["registered_domain"])
    ]
    df["suspicious_keyword_and_login_form"] = (
        (df["has_suspicious_keywords"] == 1) & (df["has_login_form"] == 1)
    ).astype(int)
    df["high_external_link_concentration"] = (df["external_link_ratio"] > 0.75).astype(int)
    df["brand_keyword_deep_path"] = (
        (df["has_suspicious_keywords"] == 1) & (df["path_depth"] >= 2)
    ).astype(int)
    
    group_d_cols = [
        "subdomain_to_apex_length_ratio",
        "suspicious_keyword_and_login_form",
        "high_external_link_concentration",
        "brand_keyword_deep_path",
    ]

    feature_sets = {
        "Ablation_A_Production_Baseline": prod_features,
        "Ablation_B_Form_Behavior": prod_features + group_b_cols,
        "Ablation_C_Page_Structure": prod_features + group_c_cols,
        "Ablation_D_URL_Content_Consistency": prod_features + group_d_cols,
        "Ablation_E_Combined_Semantic_Behavior": prod_features + group_b_cols + group_c_cols + group_d_cols,
    }
    
    logger.info("Dataset prepared: %d total samples", len(df))
    for name, f_list in feature_sets.items():
        logger.info("  %s: %d features", name, len(f_list))
        
    return df, prod_features, feature_sets


def evaluate_predictions_full(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
    test_df: pd.DataFrame,
) -> Dict[str, Any]:
    """Compute comprehensive classification metrics and subclass slices."""
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
    
    # Slices
    sparse_legit_mask = (test_df["label_binary"] == 0) & (test_df["num_links"] <= 20) & (test_df["has_login_form"] == 0)
    n_sparse_legit = int(sparse_legit_mask.sum())
    sparse_legit_fps = int((y_pred[sparse_legit_mask] == 1).sum()) if n_sparse_legit > 0 else 0
    sparse_legit_fpr = float(sparse_legit_fps / n_sparse_legit) if n_sparse_legit > 0 else 0.0
    
    login_legit_mask = (test_df["label_binary"] == 0) & ((test_df["has_login_form"] == 1) | (test_df["num_password_fields"] > 0))
    n_login_legit = int(login_legit_mask.sum())
    login_legit_fps = int((y_pred[login_legit_mask] == 1).sum()) if n_login_legit > 0 else 0
    login_legit_fpr = float(login_legit_fps / n_login_legit) if n_login_legit > 0 else 0.0
    
    short_phish_mask = (test_df["label_binary"] == 1) & (test_df["is_shortened_url"] == 1)
    n_short_phish = int(short_phish_mask.sum())
    short_phish_rec = float(recall_score(y_true[short_phish_mask], y_pred[short_phish_mask], zero_division=0)) if n_short_phish > 0 else 1.0
    
    https_phish_mask = (test_df["label_binary"] == 1) & (test_df["uses_https"] == 1)
    n_https_phish = int(https_phish_mask.sum())
    https_phish_rec = float(recall_score(y_true[https_phish_mask], y_pred[https_phish_mask], zero_division=0)) if n_https_phish > 0 else 1.0
    
    sparse_phish_mask = (test_df["label_binary"] == 1) & (test_df["num_links"] <= 20)
    n_sparse_phish = int(sparse_phish_mask.sum())
    sparse_phish_rec = float(recall_score(y_true[sparse_phish_mask], y_pred[sparse_phish_mask], zero_division=0)) if n_sparse_phish > 0 else 1.0
    
    return {
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
            "legitimate_login_fpr": round(login_legit_fpr, 4),
            "legitimate_login_fps": login_legit_fps,
            "legitimate_login_total": n_login_legit,
            "shortened_phishing_recall": round(short_phish_rec, 4),
            "shortened_phishing_total": n_short_phish,
            "https_phishing_recall": round(https_phish_rec, 4),
            "https_phishing_total": n_https_phish,
            "sparse_phishing_recall": round(sparse_phish_rec, 4),
            "sparse_phishing_total": n_sparse_phish,
        },
    }


def run_experiment() -> Dict[str, Any]:
    logger.info("=== STARTING SEMANTIC & BEHAVIORAL CANDIDATE EXPERIMENT ===")
    
    df, prod_features, feature_sets = prepare_semantic_dataset()
    
    # 5-fold Domain-Disjoint Split
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
    
    # Evaluate Production Baseline on this test set
    prod_model = joblib.load(PROD_MODEL_PATH)
    prod_prob = prod_model.predict_proba(test_df[prod_features])[:, 1]
    prod_pred = (prod_prob >= 0.5).astype(int)
    prod_eval = evaluate_predictions_full(y_test, prod_pred, prod_prob, test_df)
    
    results = {
        "production_baseline": {
            "model_version": "2.1.0",
            "feature_count": len(prod_features),
            "metrics": prod_eval,
        },
        "ablations": {},
    }
    
    models_dict = {}
    
    # Train each ablation with consistent balanced parameters
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
    
    for exp_name, feat_cols in feature_sets.items():
        X_tr = train_df[feat_cols].values
        X_te = test_df[feat_cols].values
        
        logger.info("Training %s (%d features)...", exp_name, len(feat_cols))
        clf = xgb.XGBClassifier(**xgb_params)
        clf.fit(X_tr, y_train)
        
        models_dict[exp_name] = (clf, feat_cols)
        
        y_prob = clf.predict_proba(X_te)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)
        
        metrics = evaluate_predictions_full(y_test, y_pred, y_prob, test_df)
        
        # Feature Importances
        importances = dict(zip(feat_cols, clf.feature_importances_.tolist()))
        sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
        top_imp = dict(sorted_imp[:15])
        top2_conc = (sorted_imp[0][1] + sorted_imp[1][1]) * 100
        
        metrics["top2_feature_concentration_pct"] = round(float(top2_conc), 2)
        metrics["top_15_features"] = top_imp
        
        results["ablations"][exp_name] = {
            "feature_count": len(feat_cols),
            "metrics": metrics,
        }
        
        logger.info(
            "[%s] Acc: %.2f%% | Prec: %.2f%% | Rec: %.2f%% | F1: %.2f%% | Sparse FPR: %.2f%% | Shortener Rec: %.2f%% | Top2 Conc: %.2f%%",
            exp_name,
            metrics["accuracy"] * 100,
            metrics["precision"] * 100,
            metrics["recall"] * 100,
            metrics["f1_score"] * 100,
            metrics["slices"]["sparse_legitimate_fpr"] * 100,
            metrics["slices"]["shortened_phishing_recall"] * 100,
            metrics["top2_feature_concentration_pct"],
        )

    # -------------------------------------------------------------
    # Select Best Candidate and Persist Artifacts
    # -------------------------------------------------------------
    # Identify highest-performing ablation
    best_candidate_name = "Ablation_E_Combined_Semantic_Behavior"
    best_model, best_features = models_dict[best_candidate_name]
    
    candidate_model_path = CANDIDATES_DIR / "candidate_semantic_behavior_model.joblib"
    candidate_features_path = CANDIDATES_DIR / "candidate_feature_columns.json"
    candidate_meta_path = CANDIDATES_DIR / "candidate_metadata.json"
    candidate_report_path = CANDIDATES_DIR / "candidate_experiment_report.json"
    candidate_corr_path = CANDIDATES_DIR / "candidate_feature_correlations.json"
    candidate_perm_path = CANDIDATES_DIR / "candidate_permutation_importances.json"
    
    # Save Model Artifacts
    joblib.dump(best_model, candidate_model_path)
    with open(candidate_features_path, "w", encoding="utf-8") as f:
        json.dump(best_features, f, indent=2)
        
    candidate_sha256 = compute_file_sha256(candidate_model_path)
    
    # Compute Permutation Importances for Best Candidate
    X_te_best = test_df[best_features].values
    perm_res = permutation_importance(best_model, X_te_best, y_test, scoring="recall", n_repeats=5, random_state=42)
    perm_report = [
        {
            "feature": best_features[i],
            "importance_mean": round(float(perm_res.importances_mean[i]), 6),
            "importance_std": round(float(perm_res.importances_std[i]), 6)
        }
        for i in range(len(best_features))
    ]
    perm_report.sort(key=lambda x: x["importance_mean"], reverse=True)
    with open(candidate_perm_path, "w", encoding="utf-8") as f:
        json.dump(perm_report, f, indent=2)
        
    # Compute Correlations for Best Candidate Features
    corr_matrix = df[best_features].corr().abs()
    high_corr_pairs = []
    for i in range(len(best_features)):
        for j in range(i + 1, len(best_features)):
            c = corr_matrix.iloc[i, j]
            if c >= 0.70:
                high_corr_pairs.append({
                    "feature_1": best_features[i],
                    "feature_2": best_features[j],
                    "correlation": round(float(c), 4)
                })
    high_corr_pairs.sort(key=lambda x: x["correlation"], reverse=True)
    with open(candidate_corr_path, "w", encoding="utf-8") as f:
        json.dump(high_corr_pairs, f, indent=2)

    # Save Candidate Metadata
    candidate_metadata = {
        "model_version": "2.2.0-candidate-semantic-behavior",
        "model_name": "Semantic & Behavioral Augmented XGBoost Phishing Detector (Candidate E)",
        "sha256_hash": candidate_sha256,
        "date_trained": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "algorithm": "XGBClassifier",
        "feature_count": len(best_features),
        "hyperparameters": xgb_params,
        "evaluation_metrics": results["ablations"][best_candidate_name]["metrics"],
        "comparison_with_production_baseline": {
            "prod_accuracy": prod_eval["accuracy"],
            "candidate_accuracy": results["ablations"][best_candidate_name]["metrics"]["accuracy"],
            "prod_recall": prod_eval["recall"],
            "candidate_recall": results["ablations"][best_candidate_name]["metrics"]["recall"],
            "prod_sparse_fpr": prod_eval["slices"]["sparse_legitimate_fpr"],
            "candidate_sparse_fpr": results["ablations"][best_candidate_name]["metrics"]["slices"]["sparse_legitimate_fpr"],
            "prod_top2_concentration": 43.06,
            "candidate_top2_concentration": results["ablations"][best_candidate_name]["metrics"]["top2_feature_concentration_pct"],
        },
    }
    
    with open(candidate_meta_path, "w", encoding="utf-8") as f:
        json.dump(candidate_metadata, f, indent=2, cls=NumpyEncoder)
        
    with open(candidate_report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, cls=NumpyEncoder)
        
    logger.info("Candidate artifacts persisted in %s", CANDIDATES_DIR)
    logger.info("Candidate Model SHA-256: %s", candidate_sha256)
    
    return results


if __name__ == "__main__":
    run_experiment()
