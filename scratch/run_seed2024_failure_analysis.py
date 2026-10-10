"""Failure Analysis Experiment for Semantic Candidate on Seed 2024 Out-of-Domain Split.

Analyzes why the semantic candidate (54 features) had 136 false negatives vs 100 false negatives
for the baseline model (43 features) on Seed 2024 (GroupShuffleSplit random_state=2024).

Tasks:
1. Split dataset with GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=2024).
2. Train baseline model (43 features) and semantic candidate (54 features).
3. Evaluate both on identical held-out test rows.
4. Extract all false negatives for baseline (100 FNs) and semantic candidate (136 FNs).
5. Extract the 36 additional false negatives (detected by baseline, missed by semantic).
6. Record URL, apex domain, scores, score difference, all feature values, slice tags.
7. Perform feature distribution and importance comparison (tree gain + permutation recall).
8. Diagnose over-reliance on HTTPS, page structure, form behavior, external links, brand cues.
9. Output results to scratch/semantic_seed2024_failure_analysis.json.
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
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("failure_analysis")

BACKEND_DIR = Path("backend")
MODELS_DIR = BACKEND_DIR / "ml" / "models"
PROD_MODEL_PATH = MODELS_DIR / "phishing_model.joblib"
DATA_DIR = BACKEND_DIR / "data" / "processed"
SCRATCH_DIR = Path("scratch")
SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
OUT_JSON_PATH = SCRATCH_DIR / "semantic_seed2024_failure_analysis.json"


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


def prepare_data():
    raw_df = pd.read_csv(DATA_DIR / "training_dataset_expanded.csv")
    df = raw_df.copy()
    df["label_binary"] = df["label"].apply(lambda v: 1 if str(v).lower().strip() in ["1", "phishing"] else 0)
    df["registered_domain"] = df["url"].apply(extract_registered_domain)
    
    with open(MODELS_DIR / "feature_columns.json", "r", encoding="utf-8") as f:
        prod_features = json.load(f)
        
    # Semantic & Behavioral Features
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
    
    semantic_features = prod_features + [
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
    
    return df, prod_features, semantic_features


def main():
    logger.info("Starting Seed 2024 Failure Analysis Experiment...")
    
    prod_sha256_before = compute_sha256(PROD_MODEL_PATH)
    logger.info("Production Model SHA-256 before analysis: %s", prod_sha256_before)
    
    df, prod_features, semantic_features = prepare_data()
    
    # 1. Split on Seed 2024
    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=2024)
    train_idx, test_idx = next(gss.split(df, df["label_binary"], df["registered_domain"]))
    
    train_df = df.iloc[train_idx].copy()
    test_df = df.iloc[test_idx].copy()
    
    train_domains = set(train_df["registered_domain"])
    test_domains = set(test_df["registered_domain"])
    overlap = train_domains.intersection(test_domains)
    assert len(overlap) == 0, "Domain overlap detected!"
    
    logger.info("Seed 2024 split: Train=%d samples (%d domains) | Test=%d samples (%d domains)",
                len(train_df), len(train_domains), len(test_df), len(test_domains))
    
    y_train = train_df["label_binary"].values
    y_test = test_df["label_binary"].values
    
    # 2. Train both models on Seed 2024 training partition
    xgb_params = {
        "max_depth": 4,
        "learning_rate": 0.05,
        "n_estimators": 200,
        "colsample_bytree": 0.70,
        "subsample": 0.95,
        "reg_lambda": 1.0,
        "scale_pos_weight": 5.0,
        "random_state": 2024,
        "eval_metric": "logloss",
        "n_jobs": -1
    }
    
    logger.info("Training Baseline model (43 features) on Seed 2024...")
    clf_base = XGBClassifier(**xgb_params)
    clf_base.fit(train_df[prod_features], y_train)
    prob_base = clf_base.predict_proba(test_df[prod_features])[:, 1]
    pred_base = (prob_base >= 0.5).astype(int)
    
    logger.info("Training Semantic model (54 features) on Seed 2024...")
    clf_sem = XGBClassifier(**xgb_params)
    clf_sem.fit(train_df[semantic_features], y_train)
    prob_sem = clf_sem.predict_proba(test_df[semantic_features])[:, 1]
    pred_sem = (prob_sem >= 0.5).astype(int)
    
    # 3. Overall Performance
    acc_base = accuracy_score(y_test, pred_base)
    rec_base = recall_score(y_test, pred_base)
    prec_base = precision_score(y_test, pred_base, zero_division=0)
    cm_base = confusion_matrix(y_test, pred_base)
    
    acc_sem = accuracy_score(y_test, pred_sem)
    rec_sem = recall_score(y_test, pred_sem)
    prec_sem = precision_score(y_test, pred_sem, zero_division=0)
    cm_sem = confusion_matrix(y_test, pred_sem)
    
    logger.info("Baseline: Acc=%.2f%% | Rec=%.2f%% (FN=%d, TP=%d, FP=%d, TN=%d)",
                acc_base * 100, rec_base * 100, cm_base[1, 0], cm_base[1, 1], cm_base[0, 1], cm_base[0, 0])
    logger.info("Semantic: Acc=%.2f%% | Rec=%.2f%% (FN=%d, TP=%d, FP=%d, TN=%d)",
                acc_sem * 100, rec_sem * 100, cm_sem[1, 0], cm_sem[1, 1], cm_sem[0, 1], cm_sem[0, 0])
    
    # 4. Extract False Negatives
    phish_mask = (y_test == 1)
    base_fn_mask = phish_mask & (pred_base == 0)
    sem_fn_mask = phish_mask & (pred_sem == 0)
    additional_fn_mask = phish_mask & (pred_base == 1) & (pred_sem == 0)  # The 36 additional FNs
    
    test_df_eval = test_df.copy()
    test_df_eval["prob_base"] = prob_base
    test_df_eval["prob_sem"] = prob_sem
    test_df_eval["score_diff_sem_minus_base"] = prob_sem - prob_base
    test_df_eval["pred_base"] = pred_base
    test_df_eval["pred_sem"] = pred_sem
    test_df_eval["is_sparse_page"] = (test_df_eval["num_links"] <= 20).astype(int)
    
    additional_fns_df = test_df_eval[additional_fn_mask].copy()
    all_sem_fns_df = test_df_eval[sem_fn_mask].copy()
    all_base_fns_df = test_df_eval[base_fn_mask].copy()
    
    logger.info("Additional False Negatives count: %d", len(additional_fns_df))
    
    # 5. Profile the 36 Additional False Negatives
    # Detailed record for each of the 36 additional false negatives
    additional_fn_records = []
    for idx, row in additional_fns_df.iterrows():
        rec = {
            "index": int(idx),
            "url": str(row["url"]),
            "registered_domain": str(row["registered_domain"]),
            "label": "phishing",
            "baseline_score": round(float(row["prob_base"]), 4),
            "semantic_score": round(float(row["prob_sem"]), 4),
            "score_difference": round(float(row["score_diff_sem_minus_base"]), 4),
            "slices": {
                "uses_https": int(row["uses_https"]),
                "is_shortened_url": int(row["is_shortened_url"]),
                "is_sparse_page": int(row["is_sparse_page"]),
                "has_login_form": int(row["has_login_form"]),
                "has_external_form": int(row["num_forms_with_external_action"] > 0),
            },
            "semantic_features": {
                "password_field_present": int(row["password_field_present"]),
                "external_form_action_ratio": round(float(row["external_form_action_ratio"]), 4),
                "credential_collection_pattern": int(row["credential_collection_pattern"]),
                "meta_refresh_present": int(row["meta_refresh_present"]),
                "script_to_link_ratio": round(float(row["script_to_link_ratio"]), 4),
                "hidden_element_indicator": int(row["hidden_element_indicator"]),
                "iframe_to_image_ratio": round(float(row["iframe_to_image_ratio"]), 4),
                "subdomain_to_apex_length_ratio": round(float(row["subdomain_to_apex_length_ratio"]), 4),
                "suspicious_keyword_and_login_form": int(row["suspicious_keyword_and_login_form"]),
                "high_external_link_concentration": int(row["high_external_link_concentration"]),
                "brand_keyword_deep_path": int(row["brand_keyword_deep_path"]),
            },
            "key_production_features": {
                "num_links": int(row["num_links"]),
                "num_internal_links": int(row["num_internal_links"]),
                "num_external_links": int(row["num_external_links"]),
                "external_link_ratio": round(float(row["external_link_ratio"]), 4),
                "domain_length": int(row["domain_length"]),
                "url_length": int(row["url_length"]),
                "path_length": int(row["path_length"]),
                "num_digits": int(row["num_digits"]),
                "num_slashes": int(row["num_slashes"]),
                "has_suspicious_keywords": int(row["has_suspicious_keywords"]),
                "has_login_form": int(row["has_login_form"]),
            }
        }
        additional_fn_records.append(rec)
        
    # Statistical profiling of the 36 additional FNs vs correctly detected phishing vs legitimate
    detected_phish_df = test_df_eval[phish_mask & (pred_sem == 1)]
    legit_test_df = test_df_eval[test_df_eval["label_binary"] == 0]
    
    def feature_profile(df_subset, cols):
        prof = {}
        for c in cols:
            prof[c] = {
                "mean": round(float(df_subset[c].mean()), 4),
                "median": round(float(df_subset[c].median()), 4),
                "pct_nonzero": round(float((df_subset[c] > 0).mean() * 100), 2)
            }
        return prof

    semantic_cols_to_check = [
        "password_field_present", "external_form_action_ratio", "credential_collection_pattern",
        "meta_refresh_present", "script_to_link_ratio", "hidden_element_indicator",
        "iframe_to_image_ratio", "subdomain_to_apex_length_ratio", "suspicious_keyword_and_login_form",
        "high_external_link_concentration", "brand_keyword_deep_path"
    ]
    
    prod_cols_to_check = [
        "num_links", "num_internal_links", "num_external_links", "external_link_ratio",
        "uses_https", "domain_length", "url_length", "has_suspicious_keywords", "has_login_form"
    ]
    
    profile_36_fns = feature_profile(additional_fns_df, semantic_cols_to_check + prod_cols_to_check)
    profile_detected_phish = feature_profile(detected_phish_df, semantic_cols_to_check + prod_cols_to_check)
    profile_legit = feature_profile(legit_test_df, semantic_cols_to_check + prod_cols_to_check)
    
    # 6. Feature Importances Comparison (Tree Gain + Permutation Recall)
    # Tree gain
    gain_base = dict(zip(prod_features, clf_base.feature_importances_.tolist()))
    gain_sem = dict(zip(semantic_features, clf_sem.feature_importances_.tolist()))
    
    # Permutation Recall Importances
    perm_base = permutation_importance(clf_base, test_df[prod_features], y_test, scoring="recall", n_repeats=5, random_state=2024)
    perm_sem = permutation_importance(clf_sem, test_df[semantic_features], y_test, scoring="recall", n_repeats=5, random_state=2024)
    
    perm_base_list = [
        {"feature": prod_features[i], "mean": round(float(perm_base.importances_mean[i]), 6), "std": round(float(perm_base.importances_std[i]), 6)}
        for i in range(len(prod_features))
    ]
    perm_base_list.sort(key=lambda x: x["mean"], reverse=True)
    
    perm_sem_list = [
        {"feature": semantic_features[i], "mean": round(float(perm_sem.importances_mean[i]), 6), "std": round(float(perm_sem.importances_std[i]), 6)}
        for i in range(len(semantic_features))
    ]
    perm_sem_list.sort(key=lambda x: x["mean"], reverse=True)
    
    # 7. Identify Root Causes of the Recall Loss on Seed 2024
    # Check why additional 36 FNs scored < 0.5 in Semantic Model while scoring >= 0.5 in Baseline
    # Specifically, check the feature values of these 36 FNs:
    # Are they HTTPS? Are they low links? Are they missing login forms? Are they missing suspicious keywords?
    root_cause_findings = {
        "https_pct_in_36_fns": round(float(additional_fns_df["uses_https"].mean() * 100), 2),
        "sparse_pct_in_36_fns": round(float(additional_fns_df["is_sparse_page"].mean() * 100), 2),
        "login_form_pct_in_36_fns": round(float(additional_fns_df["has_login_form"].mean() * 100), 2),
        "password_field_pct_in_36_fns": round(float(additional_fns_df["password_field_present"].mean() * 100), 2),
        "external_form_action_pct_in_36_fns": round(float((additional_fns_df["num_forms_with_external_action"] > 0).mean() * 100), 2),
        "high_external_link_pct_in_36_fns": round(float(additional_fns_df["high_external_link_concentration"].mean() * 100), 2),
        "suspicious_keywords_pct_in_36_fns": round(float(additional_fns_df["has_suspicious_keywords"].mean() * 100), 2),
        "avg_baseline_score": round(float(additional_fns_df["prob_base"].mean()), 4),
        "avg_semantic_score": round(float(additional_fns_df["prob_sem"].mean()), 4),
        "avg_score_drop": round(float((additional_fns_df["prob_base"] - additional_fns_df["prob_sem"]).mean()), 4),
        "sample_affected_domains": list(additional_fns_df["registered_domain"].unique()[:15]),
    }
    
    failure_report = {
        "report_title": "Seed 2024 Failure Analysis: Semantic Candidate vs Baseline",
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "seed": 2024,
        "sample_counts": {
            "total_test": len(test_df),
            "phishing_test": int(phish_mask.sum()),
            "legitimate_test": int((y_test == 0).sum()),
            "test_domains": len(test_domains),
            "train_domains": len(train_domains),
        },
        "overall_performance": {
            "baseline_43_features": {
                "accuracy": round(float(acc_base), 4),
                "recall": round(float(rec_base), 4),
                "precision": round(float(prec_base), 4),
                "fn_count": int(cm_base[1, 0]),
                "tp_count": int(cm_base[1, 1]),
                "fp_count": int(cm_base[0, 1]),
                "tn_count": int(cm_base[0, 0]),
            },
            "semantic_54_features": {
                "accuracy": round(float(acc_sem), 4),
                "recall": round(float(rec_sem), 4),
                "precision": round(float(prec_sem), 4),
                "fn_count": int(cm_sem[1, 0]),
                "tp_count": int(cm_sem[1, 1]),
                "fp_count": int(cm_sem[0, 1]),
                "tn_count": int(cm_sem[0, 0]),
            },
            "delta_semantic_minus_baseline": {
                "accuracy_diff": round(float(acc_sem - acc_base), 4),
                "recall_diff": round(float(rec_sem - rec_base), 4),
                "precision_diff": round(float(prec_sem - prec_base), 4),
                "additional_false_negatives": int(cm_sem[1, 0] - cm_base[1, 0]),
                "false_positive_reduction": int(cm_base[0, 1] - cm_sem[0, 1]),
            }
        },
        "root_cause_findings": root_cause_findings,
        "feature_profiles": {
            "additional_36_false_negatives": profile_36_fns,
            "correctly_detected_phishing": profile_detected_phish,
            "legitimate_pages": profile_legit,
        },
        "feature_importances": {
            "tree_gain_baseline": gain_base,
            "tree_gain_semantic": gain_sem,
            "permutation_recall_baseline": perm_base_list[:15],
            "permutation_recall_semantic": perm_sem_list[:15],
        },
        "additional_36_false_negative_samples": additional_fn_records,
    }
    
    with open(OUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(failure_report, f, indent=2, cls=NumpyEncoder)
        
    prod_sha256_after = compute_sha256(PROD_MODEL_PATH)
    assert prod_sha256_before == prod_sha256_after, "CRITICAL ERROR: Production model SHA-256 modified!"
    logger.info("Verified: Production Model SHA-256 remains 100%% untouched (%s)", prod_sha256_after)
    logger.info("Failure analysis JSON written to %s", OUT_JSON_PATH)
    
    return failure_report


if __name__ == "__main__":
    main()
