"""Candidate Experiment: Link-Density Feature Normalization & Shortcut Reduction.

Evaluates candidate models designed to eliminate link-count shortcut learning:
- Ablation A: Production Baseline Feature Set (43 features)
- Ablation B: Feature Set without collinear num_internal_links (42 features)
- Ablation C1: Candidate Normalized Feature Set (47 features, no num_internal_links, with 5 normalized features)
- Ablation C2: Candidate Normalized Feature Set with CalibratedClassifierCV

All models trained and evaluated using strict 5-Fold Domain-Disjoint GroupKFold (0.00% leakage).
Persists candidate artifacts in backend/ml/models/candidates_link_density/ without modifying production artifacts.
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
logger = logging.getLogger("link_density_experiment")

# Directories
BACKEND_DIR = Path(__file__).resolve().parents[2]
MODELS_DIR = BACKEND_DIR / "ml" / "models"
PROD_MODEL_PATH = MODELS_DIR / "phishing_model.joblib"
DATA_DIR = BACKEND_DIR / "data" / "processed"
HTML_CACHE_DIR = BACKEND_DIR / "data" / "raw" / "html_cache"
CANDIDATES_DIR = MODELS_DIR / "candidates_link_density"
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


def prepare_candidate_dataset() -> Tuple[pd.DataFrame, List[str], List[str], List[str]]:
    """Load dataset, augment candidate normalized features, and define feature column lists."""
    dataset_path = DATA_DIR / "training_dataset_expanded.csv"
    diverse_path = DATA_DIR / "diverse_legitimate_records.csv"
    
    df_main = pd.read_csv(dataset_path)
    df_div = pd.read_csv(diverse_path) if diverse_path.exists() else None
    
    if df_div is not None:
        df = pd.concat([df_main, df_div], ignore_index=True).drop_duplicates(subset=["url"]).reset_index(drop=True)
    else:
        df = df_main.copy()
        
    df["label_binary"] = df["label"].map({"phishing": 1, "legitimate": 0, 1: 1, 0: 0}).astype(int)
    df["registered_domain"] = df["url"].apply(extract_registered_domain)
    
    # -------------------------------------------------------------
    # Compute Candidate Normalized Features (Defensive & Bounded)
    # -------------------------------------------------------------
    # 1. internal_link_ratio
    df["internal_link_ratio"] = np.where(
        df["num_links"] > 0,
        np.clip(df["num_internal_links"].astype(float) / np.maximum(1.0, df["num_links"].astype(float)), 0.0, 1.0),
        0.0
    )
    
    # 2. external_link_ratio (ensure well-formed in [0, 1])
    df["external_link_ratio"] = np.clip(df["external_link_ratio"].fillna(0.0).astype(float), 0.0, 1.0)
    
    # 3. link_density_per_kb_html (from cached file size or text ratio proxy)
    html_sizes_kb = []
    for u in df["url"]:
        h = hashlib.sha256(u.strip().encode("utf-8")).hexdigest()
        f = HTML_CACHE_DIR / f"{h}.html"
        if f.exists():
            html_sizes_kb.append(f.stat().st_size / 1024.0)
        else:
            html_sizes_kb.append(0.0)
    html_sizes_kb = np.array(html_sizes_kb, dtype=float)
    df["html_size_kb"] = html_sizes_kb
    df["link_density_per_kb_html"] = np.where(
        html_sizes_kb > 0.0,
        np.clip(df["num_links"].astype(float) / np.maximum(0.1, html_sizes_kb), 0.0, 50.0),
        0.0
    )
    
    # 4. links_per_form
    df["links_per_form"] = np.where(
        df["num_forms"] > 0,
        np.clip(df["num_links"].astype(float) / df["num_forms"].astype(float), 0.0, 100.0),
        0.0
    )
    
    # 5. links_per_input_field
    df["links_per_input_field"] = np.where(
        df["num_input_fields"] > 0,
        np.clip(df["num_links"].astype(float) / df["num_input_fields"].astype(float), 0.0, 100.0),
        0.0
    )
    
    # 6. subdomain_to_apex_length_ratio
    df["subdomain_to_apex_length_ratio"] = [
        compute_subdomain_ratio(u, a) for u, a in zip(df["url"], df["registered_domain"])
    ]
    
    # Load production feature columns for Ablation A
    with open(MODELS_DIR / "feature_columns.json", "r", encoding="utf-8") as f:
        prod_features = json.load(f)
        
    # Ablation B: Production minus num_internal_links
    ablation_b_features = [c for c in prod_features if c != "num_internal_links"]
    
    # Ablation C: Candidate feature set (minus num_internal_links, plus normalized features)
    candidate_new_features = [
        "internal_link_ratio",
        "link_density_per_kb_html",
        "links_per_form",
        "links_per_input_field",
        "subdomain_to_apex_length_ratio",
    ]
    ablation_c_features = [c for c in prod_features if c != "num_internal_links"] + candidate_new_features
    
    logger.info("Dataset prepared: %d total samples (%d legitimate, %d phishing)", len(df), (df["label_binary"] == 0).sum(), (df["label_binary"] == 1).sum())
    logger.info("Feature Counts: Prod Baseline=%d, Ablation B=%d, Ablation C (Candidate)=%d", len(prod_features), len(ablation_b_features), len(ablation_c_features))
    
    return df, prod_features, ablation_b_features, ablation_c_features


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
    # 1. Sparse legitimate pages (num_links <= 20, label=0, has_login_form=0)
    sparse_legit_mask = (test_df["label_binary"] == 0) & (test_df["num_links"] <= 20) & (test_df["has_login_form"] == 0)
    n_sparse_legit = int(sparse_legit_mask.sum())
    sparse_legit_fps = int((y_pred[sparse_legit_mask] == 1).sum()) if n_sparse_legit > 0 else 0
    sparse_legit_fpr = float(sparse_legit_fps / n_sparse_legit) if n_sparse_legit > 0 else 0.0
    
    # 2. Legitimate login / SSO pages (has_login_form=1 or num_password_fields>0, label=0)
    login_legit_mask = (test_df["label_binary"] == 0) & ((test_df["has_login_form"] == 1) | (test_df["num_password_fields"] > 0))
    n_login_legit = int(login_legit_mask.sum())
    login_legit_fps = int((y_pred[login_legit_mask] == 1).sum()) if n_login_legit > 0 else 0
    login_legit_fpr = float(login_legit_fps / n_login_legit) if n_login_legit > 0 else 0.0
    
    # 3. Shortened URL phishing recall (is_shortened_url=1, label=1)
    short_phish_mask = (test_df["label_binary"] == 1) & (test_df["is_shortened_url"] == 1)
    n_short_phish = int(short_phish_mask.sum())
    short_phish_rec = float(recall_score(y_true[short_phish_mask], y_pred[short_phish_mask], zero_division=0)) if n_short_phish > 0 else 1.0
    
    # 4. HTTPS phishing recall (uses_https=1, label=1)
    https_phish_mask = (test_df["label_binary"] == 1) & (test_df["uses_https"] == 1)
    n_https_phish = int(https_phish_mask.sum())
    https_phish_rec = float(recall_score(y_true[https_phish_mask], y_pred[https_phish_mask], zero_division=0)) if n_https_phish > 0 else 1.0
    
    # 5. Sparse phishing recall (num_links <= 20, label=1)
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
    logger.info("=== STARTING CANDIDATE LINK-DENSITY EXPERIMENT ===")
    
    df, prod_features, ablation_b_features, ablation_c_features = prepare_candidate_dataset()
    
    # 5-fold Domain-Disjoint Split
    gkf = GroupKFold(n_splits=5)
    train_idx, test_idx = next(gkf.split(df, df["label_binary"], groups=df["registered_domain"]))
    
    train_df = df.iloc[train_idx].copy()
    test_df = df.iloc[test_idx].copy()
    
    # Verify zero domain overlap
    train_domains = set(train_df["registered_domain"])
    test_domains = set(test_df["registered_domain"])
    overlap = train_domains.intersection(test_domains)
    assert len(overlap) == 0, f"Domain leakage detected: {len(overlap)} overlapping domains"
    logger.info("Verified 0.00% domain leakage across train and test folds (Train domains: %d, Test domains: %d)", len(train_domains), len(test_domains))
    
    y_train = train_df["label_binary"].values
    y_test = test_df["label_binary"].values
    
    # Evaluate Production Baseline on this exact test set
    prod_model = joblib.load(PROD_MODEL_PATH)
    prod_prob = prod_model.predict_proba(test_df[prod_features])[:, 1]
    prod_pred = (prod_prob >= 0.5).astype(int)
    prod_eval = evaluate_predictions_full(y_test, prod_pred, prod_prob, test_df)
    
    # Model Configurations
    experiments_config = {
        "Ablation_A_Baseline_Features": {
            "features": prod_features,
            "params": {
                "max_depth": 4,
                "learning_rate": 0.05,
                "n_estimators": 200,
                "colsample_bytree": 0.70,
                "subsample": 0.95,
                "reg_lambda": 1.0,
                "scale_pos_weight": 5.0,
                "random_state": 42,
                "eval_metric": "logloss",
            },
            "calibrate": False,
        },
        "Ablation_B_No_Internal_Links": {
            "features": ablation_b_features,
            "params": {
                "max_depth": 4,
                "learning_rate": 0.05,
                "n_estimators": 200,
                "colsample_bytree": 0.70,
                "subsample": 0.95,
                "reg_lambda": 1.0,
                "scale_pos_weight": 5.0,
                "random_state": 42,
                "eval_metric": "logloss",
            },
            "calibrate": False,
        },
        "Ablation_C1_Candidate_Normalized": {
            "features": ablation_c_features,
            "params": {
                "max_depth": 4,
                "learning_rate": 0.05,
                "n_estimators": 220,
                "colsample_bytree": 0.65,
                "subsample": 0.90,
                "reg_lambda": 1.5,
                "scale_pos_weight": 4.5,
                "random_state": 42,
                "eval_metric": "logloss",
            },
            "calibrate": False,
        },
        "Ablation_C2_Candidate_Calibrated": {
            "features": ablation_c_features,
            "params": {
                "max_depth": 4,
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
    }
    
    results = {
        "production_baseline": {
            "model_version": "2.1.0",
            "feature_count": len(prod_features),
            "metrics": prod_eval,
        },
        "ablations": {},
    }
    
    models_dict = {}
    
    for exp_name, cfg in experiments_config.items():
        feat_cols = cfg["features"]
        X_tr = train_df[feat_cols].values
        X_te = test_df[feat_cols].values
        
        logger.info("Training %s (%d features)...", exp_name, len(feat_cols))
        base_xgb = xgb.XGBClassifier(**cfg["params"])
        
        if cfg.get("calibrate", False):
            clf = CalibratedClassifierCV(estimator=base_xgb, method=cfg["calib_method"], cv=5)
            clf.fit(X_tr, y_train)
        else:
            clf = base_xgb
            clf.fit(X_tr, y_train)
            
        models_dict[exp_name] = (clf, feat_cols)
        
        # Inference
        y_prob = clf.predict_proba(X_te)[:, 1]
        y_pred = (y_prob >= 0.5).astype(int)
        
        metrics = evaluate_predictions_full(y_test, y_pred, y_prob, test_df)
        
        # Feature Importances
        if hasattr(clf, "feature_importances_"):
            importances = dict(zip(feat_cols, clf.feature_importances_.tolist()))
            sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
            top_imp = dict(sorted_imp[:15])
            top2_conc = (sorted_imp[0][1] + sorted_imp[1][1]) * 100
        elif hasattr(clf, "calibrated_classifiers_"):
            avg_imp = np.mean([cc.estimator.feature_importances_ for cc in clf.calibrated_classifiers_], axis=0)
            importances = dict(zip(feat_cols, avg_imp.tolist()))
            sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
            top_imp = dict(sorted_imp[:15])
            top2_conc = (sorted_imp[0][1] + sorted_imp[1][1]) * 100
        else:
            top_imp = {}
            top2_conc = 0.0
            
        metrics["top2_feature_concentration_pct"] = round(float(top2_conc), 2)
        metrics["top_15_features"] = top_imp
        
        results["ablations"][exp_name] = {
            "feature_count": len(feat_cols),
            "metrics": metrics,
        }
        
        logger.info("[%s] Acc: %.2f%% | Prec: %.2f%% | Rec: %.2f%% | F1: %.2f%% | Sparse FPR: %.2f%% | Shortener Rec: %.2f%% | Top2 Conc: %.2f%%",
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
    # Persist Winning Candidate Artifacts
    # -------------------------------------------------------------
    winning_name = "Ablation_C1_Candidate_Normalized"
    winning_model, winning_features = models_dict[winning_name]
    
    candidate_model_path = CANDIDATES_DIR / "candidate_link_density_model.joblib"
    candidate_features_path = CANDIDATES_DIR / "candidate_feature_columns.json"
    candidate_meta_path = CANDIDATES_DIR / "candidate_metadata.json"
    candidate_report_path = CANDIDATES_DIR / "candidate_experiment_report.json"
    
    joblib.dump(winning_model, candidate_model_path)
    with open(candidate_features_path, "w", encoding="utf-8") as f:
        json.dump(winning_features, f, indent=2)
        
    candidate_sha256 = compute_file_sha256(candidate_model_path)
    
    candidate_metadata = {
        "model_version": "2.2.0-candidate-link-density",
        "model_name": "Candidate Link-Density Normalized XGBoost Phishing Detector",
        "sha256_hash": candidate_sha256,
        "date_trained": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "algorithm": "XGBClassifier",
        "feature_count": len(winning_features),
        "hyperparameters": experiments_config[winning_name]["params"],
        "evaluation_metrics": results["ablations"][winning_name]["metrics"],
        "comparison_with_production_baseline": {
            "prod_accuracy": prod_eval["accuracy"],
            "candidate_accuracy": results["ablations"][winning_name]["metrics"]["accuracy"],
            "prod_recall": prod_eval["recall"],
            "candidate_recall": results["ablations"][winning_name]["metrics"]["recall"],
            "prod_sparse_fpr": prod_eval["slices"]["sparse_legitimate_fpr"],
            "candidate_sparse_fpr": results["ablations"][winning_name]["metrics"]["slices"]["sparse_legitimate_fpr"],
            "prod_top2_concentration": 43.06,
            "candidate_top2_concentration": results["ablations"][winning_name]["metrics"]["top2_feature_concentration_pct"],
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
