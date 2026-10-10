"""Fair Fixed-Split Benchmark for All Phishing Detector Model Candidates.

Uses the exact production split:
GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)

Evaluates on identical held-out test rows (N=1,799, 631 unseen domains):
1. Live Production Model v2.1.0 (43 features)
2. Retrained 43-Feature Baseline (43 features)
3. Link-Density Candidate (48 features)
4. Semantic/Behavior Candidate (54 features)
5. External-Link-Concentration Candidate (44 features)

Strict constraints:
- Zero production model modification.
- Zero domain overlap.
- Verification of production model SHA-256 before and after.
"""

import datetime
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
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
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("fair_benchmark")

BACKEND_DIR = Path("backend")
MODELS_DIR = BACKEND_DIR / "ml" / "models"
PROD_MODEL_PATH = MODELS_DIR / "phishing_model.joblib"
DATA_DIR = BACKEND_DIR / "data" / "processed"
SCRATCH_DIR = Path("scratch")
SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
OUT_JSON_PATH = SCRATCH_DIR / "fair_fixed_split_benchmark.json"


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


def compute_sha256(filepath: Path) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


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


def compute_subdomain_ratio(url_str: str, apex_domain: str) -> float:
    try:
        target = url_str if "://" in url_str else f"http://{url_str}"
        host = (urlparse(target).netloc or "").lower().strip().split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        apex_str = str(apex_domain).lower().strip(".")
        if host and apex_str and host != apex_str and host.endswith(apex_str):
            sub_part = host[:-len(apex_str)].rstrip(".")
            sub_len = len(sub_part)
        else:
            sub_len = 0
        return min(10.0, round(float(sub_len / max(1, len(apex_str))), 4))
    except Exception:
        return 0.0


def prepare_benchmark_dataset() -> Tuple[pd.DataFrame, Dict[str, List[str]]]:
    df = pd.read_csv(DATA_DIR / "training_dataset_expanded.csv")
    df["label_binary"] = df["label"].apply(lambda v: 1 if str(v).lower().strip() in ["1", "phishing"] else 0)
    df["registered_domain"] = df["url"].apply(extract_registered_domain)
    
    with open(MODELS_DIR / "feature_columns.json", "r", encoding="utf-8") as f:
        prod_features = json.load(f)
        
    # -------------------------------------------------------------
    # Feature Engineering for Candidate Models
    # -------------------------------------------------------------
    # 1. Link-Density Candidate Features
    df["internal_link_ratio"] = np.where(
        df["num_links"] > 0,
        np.clip(df["num_internal_links"].astype(float) / df["num_links"].astype(float), 0.0, 1.0),
        0.0
    )
    df["link_density_per_kb_html"] = np.clip(
        df["num_links"].astype(float) / np.maximum(1.0, df["text_to_html_ratio"].astype(float) * 10.0 + 1.0),
        0.0, 100.0
    )
    df["links_per_form"] = np.where(
        df["num_forms"] > 0,
        np.clip(df["num_links"].astype(float) / df["num_forms"].astype(float), 0.0, 50.0),
        df["num_links"].astype(float)
    )
    df["links_per_input_field"] = np.where(
        df["num_input_fields"] > 0,
        np.clip(df["num_links"].astype(float) / df["num_input_fields"].astype(float), 0.0, 50.0),
        df["num_links"].astype(float)
    )
    df["subdomain_to_apex_length_ratio"] = [
        compute_subdomain_ratio(u, a) for u, a in zip(df["url"], df["registered_domain"])
    ]
    
    link_density_cols = [
        c for c in prod_features if c != "num_internal_links"
    ] + [
        "internal_link_ratio",
        "link_density_per_kb_html",
        "links_per_form",
        "links_per_input_field",
        "subdomain_to_apex_length_ratio"
    ]
    
    # 2. Semantic & Behavioral Candidate Features
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
    df["suspicious_keyword_and_login_form"] = (
        (df["has_suspicious_keywords"] == 1) & (df["has_login_form"] == 1)
    ).astype(int)
    df["high_external_link_concentration"] = (df["external_link_ratio"] > 0.75).astype(int)
    df["brand_keyword_deep_path"] = (
        (df["has_suspicious_keywords"] == 1) & (df["path_depth"] >= 2)
    ).astype(int)
    
    semantic_behavior_cols = prod_features + [
        "password_field_present",
        "external_form_action_ratio",
        "credential_collection_pattern",
        "meta_refresh_present",
        "script_to_link_ratio",
        "hidden_element_indicator",
        "iframe_to_image_ratio",
        "subdomain_to_apex_length_ratio",
        "suspicious_keyword_and_login_form",
        "high_external_link_concentration",
        "brand_keyword_deep_path"
    ]
    
    # 3. External Link Concentration Feature
    ext_link_cols = prod_features + ["high_external_link_concentration"]
    
    feature_sets = {
        "production_baseline": prod_features,
        "retrained_43_feature_baseline": prod_features,
        "candidate_link_density": link_density_cols,
        "candidate_semantic_behavior": semantic_behavior_cols,
        "candidate_external_link_concentration": ext_link_cols,
    }
    
    return df, feature_sets


def evaluate_model_on_test_set(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    test_df: pd.DataFrame,
    threshold: float = 0.50,
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
    
    # Probability distribution
    phish_p = y_prob[y_true == 1]
    legit_p = y_prob[y_true == 0]
    
    prob_dist = {
        "phishing_probabilities": {
            "mean": round(float(np.mean(phish_p)), 4),
            "median": round(float(np.median(phish_p)), 4),
            "std": round(float(np.std(phish_p)), 4),
            "p10": round(float(np.percentile(phish_p, 10)), 4),
            "p25": round(float(np.percentile(phish_p, 25)), 4),
            "p50": round(float(np.percentile(phish_p, 50)), 4),
            "p75": round(float(np.percentile(phish_p, 75)), 4),
            "p90": round(float(np.percentile(phish_p, 90)), 4),
            "p95": round(float(np.percentile(phish_p, 95)), 4),
            "p99": round(float(np.percentile(phish_p, 99)), 4),
        },
        "legitimate_probabilities": {
            "mean": round(float(np.mean(legit_p)), 4),
            "median": round(float(np.median(legit_p)), 4),
            "std": round(float(np.std(legit_p)), 4),
            "p10": round(float(np.percentile(legit_p, 10)), 4),
            "p25": round(float(np.percentile(legit_p, 25)), 4),
            "p50": round(float(np.percentile(legit_p, 50)), 4),
            "p75": round(float(np.percentile(legit_p, 75)), 4),
            "p90": round(float(np.percentile(legit_p, 90)), 4),
            "p95": round(float(np.percentile(legit_p, 95)), 4),
            "p99": round(float(np.percentile(legit_p, 99)), 4),
        }
    }
    
    # Slices
    # 1. Sparse Legitimate Pages (<= 20 links)
    sparse_legit_mask = (test_df["label_binary"] == 0) & (test_df["num_links"] <= 20)
    n_sparse_legit = int(sparse_legit_mask.sum())
    sparse_legit_fps = int((y_pred[sparse_legit_mask] == 1).sum()) if n_sparse_legit > 0 else 0
    sparse_legit_fpr = float(sparse_legit_fps / n_sparse_legit) if n_sparse_legit > 0 else 0.0
    
    # 2. Sparse Phishing Pages (<= 20 links)
    sparse_phish_mask = (test_df["label_binary"] == 1) & (test_df["num_links"] <= 20)
    n_sparse_phish = int(sparse_phish_mask.sum())
    sparse_phish_rec = float(recall_score(y_true[sparse_phish_mask], y_pred[sparse_phish_mask], zero_division=0)) if n_sparse_phish > 0 else 1.0
    sparse_phish_tps = int((y_pred[sparse_phish_mask] == 1).sum()) if n_sparse_phish > 0 else 0
    
    # 3. HTTPS Phishing
    https_phish_mask = (test_df["label_binary"] == 1) & (test_df["uses_https"] == 1)
    n_https_phish = int(https_phish_mask.sum())
    https_phish_rec = float(recall_score(y_true[https_phish_mask], y_pred[https_phish_mask], zero_division=0)) if n_https_phish > 0 else 1.0
    https_phish_tps = int((y_pred[https_phish_mask] == 1).sum()) if n_https_phish > 0 else 0
    
    # 4. Shortened URLs
    short_phish_mask = (test_df["label_binary"] == 1) & (test_df["is_shortened_url"] == 1)
    n_short_phish = int(short_phish_mask.sum())
    short_phish_rec = float(recall_score(y_true[short_phish_mask], y_pred[short_phish_mask], zero_division=0)) if n_short_phish > 0 else 1.0
    short_phish_tps = int((y_pred[short_phish_mask] == 1).sum()) if n_short_phish > 0 else 0
    
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
        "accuracy": round(acc, 4),
        "recall": round(rec, 4),
        "precision": round(prec, 4),
        "f1_score": round(f1, 4),
        "specificity": round(spec, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "roc_auc": round(roc_auc, 4),
        "pr_auc": round(pr_auc, 4),
        "brier_score": round(brier, 4),
        "confusion_matrix": {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
        "probability_distribution": prob_dist,
        "slices": {
            "sparse_legitimate_fpr": round(sparse_legit_fpr, 4),
            "sparse_legitimate_fps": sparse_legit_fps,
            "sparse_legitimate_total": n_sparse_legit,
            "sparse_phishing_recall": round(sparse_phish_rec, 4),
            "sparse_phishing_tps": sparse_phish_tps,
            "sparse_phishing_total": n_sparse_phish,
            "https_phishing_recall": round(https_phish_rec, 4),
            "https_phishing_tps": https_phish_tps,
            "https_phishing_total": n_https_phish,
            "shortened_phishing_recall": round(short_phish_rec, 4),
            "shortened_phishing_tps": short_phish_tps,
            "shortened_phishing_total": n_short_phish,
            "legitimate_login_fpr": round(login_legit_fpr, 4),
            "legitimate_login_fps": login_legit_fps,
            "legitimate_login_total": n_login_legit,
            "external_form_legitimate_fpr": round(ext_form_legit_fpr, 4),
            "external_form_legitimate_fps": ext_form_legit_fps,
            "external_form_legitimate_total": n_ext_form_legit,
            "external_form_phishing_recall": round(ext_form_phish_rec, 4),
            "external_form_phishing_tps": ext_form_phish_tps,
            "external_form_phishing_total": n_ext_form_phish,
        }
    }


def run_fair_benchmark() -> Dict[str, Any]:
    logger.info("================================================================================")
    logger.info("       STARTING FAIR FIXED-SPLIT BENCHMARK FOR ALL MODEL CANDIDATES            ")
    logger.info("================================================================================")
    
    # 1. Verify production model integrity before starting
    prod_sha256_before = compute_sha256(PROD_MODEL_PATH)
    logger.info("Initial Live Production Model SHA-256: %s", prod_sha256_before)
    
    # 2. Prepare Dataset and Feature Sets
    df, feature_sets = prepare_benchmark_dataset()
    
    # 3. Exact Production Split: GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    train_idx, test_idx = next(gss.split(df, df["label_binary"], df["registered_domain"]))
    
    train_df = df.iloc[train_idx].copy()
    test_df = df.iloc[test_idx].copy()
    
    train_domains = set(train_df["registered_domain"])
    test_domains = set(test_df["registered_domain"])
    overlap = train_domains.intersection(test_domains)
    assert len(overlap) == 0, f"Domain leakage detected: {len(overlap)} overlapping domains"
    logger.info("Domain Leakage Check: 0.00% domain overlap (Train: %d domains, Test: %d domains)", len(train_domains), len(test_domains))
    logger.info("Split Sizes: Train = %d samples (%d legit, %d phish) | Test = %d samples (%d legit, %d phish)",
                len(train_df), (train_df["label_binary"] == 0).sum(), (train_df["label_binary"] == 1).sum(),
                len(test_df), (test_df["label_binary"] == 0).sum(), (test_df["label_binary"] == 1).sum())
    
    y_train = train_df["label_binary"].values
    y_test = test_df["label_binary"].values
    
    # Model Hyperparameters
    xgb_params = {
        "max_depth": 4,
        "learning_rate": 0.05,
        "n_estimators": 200,
        "colsample_bytree": 0.70,
        "subsample": 0.95,
        "reg_lambda": 1.0,
        "scale_pos_weight": 5.0,
        "random_state": 42,
        "eval_metric": "logloss",
        "n_jobs": -1
    }
    
    benchmark_results = {
        "benchmark_metadata": {
            "title": "Fair Fixed-Split Model Benchmark Across All Candidates",
            "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "split_strategy": "GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)",
            "total_samples": len(df),
            "train_samples": len(train_df),
            "test_samples": len(test_df),
            "train_domains": len(train_domains),
            "test_domains": len(test_domains),
            "domain_overlap": 0,
            "production_model_sha256": prod_sha256_before,
        },
        "models": {},
    }
    
    # -------------------------------------------------------------
    # 1. Live Production Model v2.1.0 (Evaluation on Held-Out Test Split)
    # -------------------------------------------------------------
    logger.info("Evaluating Model 1: Live Production Model v2.1.0...")
    prod_model = joblib.load(PROD_MODEL_PATH)
    prod_prob = prod_model.predict_proba(test_df[feature_sets["production_baseline"]])[:, 1]
    prod_eval = evaluate_model_on_test_set(y_test, prod_prob, test_df)
    
    benchmark_results["models"]["1_live_production_model_v2_1_0"] = {
        "model_name": "Live Production Model (v2.1.0 Champion)",
        "model_type": "Pre-trained Production Artifact",
        "feature_count": len(feature_sets["production_baseline"]),
        "evaluation_scope": "True Held-Out Generalization (GroupShuffleSplit Test Set, N=1,799)",
        "metrics": prod_eval,
    }
    
    # -------------------------------------------------------------
    # 2. Retrained 43-Feature Baseline
    # -------------------------------------------------------------
    logger.info("Training & Evaluating Model 2: Retrained 43-Feature Baseline...")
    retrained_baseline = XGBClassifier(**xgb_params)
    retrained_baseline.fit(train_df[feature_sets["retrained_43_feature_baseline"]], y_train)
    retrained_prob = retrained_baseline.predict_proba(test_df[feature_sets["retrained_43_feature_baseline"]])[:, 1]
    retrained_eval = evaluate_model_on_test_set(y_test, retrained_prob, test_df)
    
    benchmark_results["models"]["2_retrained_43_feature_baseline"] = {
        "model_name": "Retrained 43-Feature Baseline",
        "model_type": "Trained from scratch on GSS Train Partition",
        "feature_count": len(feature_sets["retrained_43_feature_baseline"]),
        "evaluation_scope": "True Held-Out Generalization (GroupShuffleSplit Test Set, N=1,799)",
        "metrics": retrained_eval,
    }
    
    # -------------------------------------------------------------
    # 3. Link-Density Candidate (48 Features)
    # -------------------------------------------------------------
    logger.info("Training & Evaluating Model 3: Link-Density Candidate (48 features)...")
    link_density_model = XGBClassifier(**xgb_params)
    link_density_model.fit(train_df[feature_sets["candidate_link_density"]], y_train)
    link_density_prob = link_density_model.predict_proba(test_df[feature_sets["candidate_link_density"]])[:, 1]
    link_density_eval = evaluate_model_on_test_set(y_test, link_density_prob, test_df)
    
    benchmark_results["models"]["3_candidate_link_density"] = {
        "model_name": "Link-Density Normalization Candidate",
        "model_type": "Trained on GSS Train Partition (num_internal_links replaced with link density ratios)",
        "feature_count": len(feature_sets["candidate_link_density"]),
        "evaluation_scope": "True Held-Out Generalization (GroupShuffleSplit Test Set, N=1,799)",
        "metrics": link_density_eval,
    }
    
    # -------------------------------------------------------------
    # 4. Semantic/Behavior Candidate (54 Features)
    # -------------------------------------------------------------
    logger.info("Training & Evaluating Model 4: Semantic & Behavioral Candidate (54 features)...")
    semantic_model = XGBClassifier(**xgb_params)
    semantic_model.fit(train_df[feature_sets["candidate_semantic_behavior"]], y_train)
    semantic_prob = semantic_model.predict_proba(test_df[feature_sets["candidate_semantic_behavior"]])[:, 1]
    semantic_eval = evaluate_model_on_test_set(y_test, semantic_prob, test_df)
    
    benchmark_results["models"]["4_candidate_semantic_behavior"] = {
        "model_name": "Semantic & Behavioral Augmented Candidate (Candidate E)",
        "model_type": "Trained on GSS Train Partition (+Form, +Structure, +Consistency)",
        "feature_count": len(feature_sets["candidate_semantic_behavior"]),
        "evaluation_scope": "True Held-Out Generalization (GroupShuffleSplit Test Set, N=1,799)",
        "metrics": semantic_eval,
    }
    
    # -------------------------------------------------------------
    # 5. External-Link-Concentration Candidate (44 Features)
    # -------------------------------------------------------------
    logger.info("Training & Evaluating Model 5: External-Link-Concentration Candidate (44 features)...")
    ext_link_model = XGBClassifier(**xgb_params)
    ext_link_model.fit(train_df[feature_sets["candidate_external_link_concentration"]], y_train)
    ext_link_prob = ext_link_model.predict_proba(test_df[feature_sets["candidate_external_link_concentration"]])[:, 1]
    ext_link_eval = evaluate_model_on_test_set(y_test, ext_link_prob, test_df)
    
    benchmark_results["models"]["5_candidate_external_link_concentration"] = {
        "model_name": "External-Link-Concentration Augmented Candidate",
        "model_type": "Trained on GSS Train Partition (+high_external_link_concentration only)",
        "feature_count": len(feature_sets["candidate_external_link_concentration"]),
        "evaluation_scope": "True Held-Out Generalization (GroupShuffleSplit Test Set, N=1,799)",
        "metrics": ext_link_eval,
    }
    
    # Log Summary Table
    logger.info("\n" + "=" * 90)
    logger.info("FAIR FIXED-SPLIT BENCHMARK SUMMARY (N=1,799 Held-Out Test Samples, 631 Unseen Domains):")
    logger.info("=" * 90)
    for k, v in benchmark_results["models"].items():
        m = v["metrics"]
        s = m["slices"]
        logger.info(
            "%-40s | Acc: %.2f%% | Rec: %.2f%% | Prec: %.2f%% | F1: %.2f%% | SparseFPR: %.2f%% | HTTPS Rec: %.2f%%",
            v["model_name"][:40],
            m["accuracy"] * 100,
            m["recall"] * 100,
            m["precision"] * 100,
            m["f1_score"] * 100,
            s["sparse_legitimate_fpr"] * 100,
            s["https_phishing_recall"] * 100,
        )
        
    # 9. Verify production model integrity after benchmark
    prod_sha256_after = compute_sha256(PROD_MODEL_PATH)
    assert prod_sha256_before == prod_sha256_after, "CRITICAL ERROR: Production model SHA-256 changed!"
    logger.info("Verified: Production Model SHA-256 remains 100%% unchanged (%s)", prod_sha256_after)
    
    with open(OUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(benchmark_results, f, indent=2, cls=NumpyEncoder)
        
    logger.info("Benchmark results written to %s", OUT_JSON_PATH)
    return benchmark_results


if __name__ == "__main__":
    run_fair_benchmark()
