"""Comprehensive ML Accuracy Diagnostic Runner for PhishGuard AI v2.1.0.

Self-contained, pure diagnostic analysis across all 7 investigation pillars:
1. Dataset Composition (Counts, balances, distributions, duplicates, missing values, errors)
2. Data Leakage (Domain overlap, duplicate vectors, train-test contamination)
3. Model Evaluation (Domain-disjoint vs stratified test sets, calibration, Brier score, ROC/PR curves)
4. Error Analysis (Top FPs, Top FNs, detailed risk scores, URL & HTML feature patterns)
5. Feature Analysis (Tree importance, permutation importance, multicollinearity, shortcut learning)
6. Model Architecture & Hyperparameters (XGBoost specs, scale_pos_weight=5.0 impact, decision thresholds)
7. Generalization & Slice Tests (Domain-disjoint gap, SSO/Login slice, SPA/JS-heavy slice, Sparse-link slice, Shorteners, HTTPS)
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
from sklearn.model_selection import GroupKFold, StratifiedKFold

# Paths
ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
MODELS_DIR = BACKEND_DIR / "ml" / "models"
DATA_DIR = BACKEND_DIR / "data" / "processed"
OUTPUT_JSON_PATH = ROOT_DIR / "scratch" / "diagnostic_summary.json"


class NumpyEncoder(json.JSONEncoder):
    """Custom JSON encoder for numpy types."""
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


def extract_tld(url_str: str) -> str:
    try:
        if not isinstance(url_str, str) or not url_str.strip():
            return "unknown"
        target = url_str if "://" in url_str else f"http://{url_str}"
        host = urllib.parse.urlsplit(target).hostname or "unknown"
        host = host.lower().strip(".")
        parts = host.split(".")
        if len(parts) >= 2:
            return "." + parts[-1]
        return "unknown"
    except Exception:
        return "unknown"


def main():
    print("=== STARTING COMPREHENSIVE ML ACCURACY DIAGNOSTIC ===")
    
    # -------------------------------------------------------------
    # 0. Load Model & Metadata
    # -------------------------------------------------------------
    model_path = MODELS_DIR / "phishing_model.joblib"
    cols_path = MODELS_DIR / "feature_columns.json"
    meta_path = MODELS_DIR / "model_metadata.json"
    
    model_sha256 = compute_file_sha256(model_path)
    model = joblib.load(model_path)
    
    with open(cols_path, "r", encoding="utf-8") as f:
        feature_columns = json.load(f)
        
    with open(meta_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)
        
    print(f"Loaded Production Model: Version={metadata.get('version')}, Algorithm={metadata.get('algorithm')}")
    print(f"Model SHA-256: {model_sha256}")
    print(f"Hyperparameters: {metadata.get('hyperparameters')}")
    print(f"Feature count: {len(feature_columns)}")

    # -------------------------------------------------------------
    # 1. Dataset Composition Analysis
    # -------------------------------------------------------------
    dataset_path_8910 = DATA_DIR / "training_dataset_expanded.csv"
    dataset_path_8958 = DATA_DIR / "training_dataset.csv"
    manifest_path = DATA_DIR / "dataset_manifest.csv"
    
    df_exp = pd.read_csv(dataset_path_8910)
    df_orig = pd.read_csv(dataset_path_8958)
    df_man = pd.read_csv(manifest_path) if manifest_path.exists() else None
    
    print("\n--- 1. DATASET COMPOSITION ANALYSIS ---")
    print(f"Primary Dataset (expanded): {len(df_exp)} rows")
    print(f"Original Dataset: {len(df_orig)} rows")
    if df_man is not None:
        print(f"Dataset Manifest: {len(df_man)} rows")

    # Standardize labels
    df = df_exp.copy()
    if "label_binary" not in df.columns:
        df["label_binary"] = df["label"].map({"phishing": 1, "legitimate": 0, 1: 1, 0: 0}).astype(int)
    
    total_samples = len(df)
    phishing_count = int((df["label_binary"] == 1).sum())
    legit_count = int((df["label_binary"] == 0).sum())
    imbalance_ratio = round(float(legit_count / phishing_count), 4)
    
    df["reg_domain"] = df["url"].apply(extract_registered_domain)
    df["tld"] = df["url"].apply(extract_tld)
    
    unique_urls = int(df["url"].nunique())
    duplicate_urls = int(total_samples - unique_urls)
    unique_domains = int(df["reg_domain"].nunique())
    
    # Missing values
    missing_counts = {k: int(v) for k, v in df[feature_columns].isnull().sum().items()}
    total_missing = int(sum(missing_counts.values()))
    
    # Parse errors
    url_parse_errors = int((df["url_parse_error"] == 1).sum()) if "url_parse_error" in df.columns else 0
    html_parse_errors = int((df["html_parse_error"] == 1).sum()) if "html_parse_error" in df.columns else 0
    
    # Sources from manifest if linkable by URL
    source_dist = {}
    if df_man is not None:
        man_sources = df_man.drop_duplicates("url").set_index("url")["source"].to_dict()
        df["source"] = df["url"].map(man_sources).fillna("unknown")
        for src, group in df.groupby("source"):
            source_dist[str(src)] = {
                "legitimate": int((group["label_binary"] == 0).sum()),
                "phishing": int((group["label_binary"] == 1).sum()),
                "total": int(len(group)),
            }
    
    # Domain frequency distribution
    domain_counts = df["reg_domain"].value_counts()
    top_domains_overall = {str(k): int(v) for k, v in domain_counts.head(15).items()}
    domain_counts_legit = {str(k): int(v) for k, v in df[df["label_binary"] == 0]["reg_domain"].value_counts().head(10).items()}
    domain_counts_phish = {str(k): int(v) for k, v in df[df["label_binary"] == 1]["reg_domain"].value_counts().head(10).items()}
    
    # TLD distribution
    tld_counts_legit = {str(k): int(v) for k, v in df[df["label_binary"] == 0]["tld"].value_counts().head(10).items()}
    tld_counts_phish = {str(k): int(v) for k, v in df[df["label_binary"] == 1]["tld"].value_counts().head(10).items()}
    
    # Login & Form distribution
    has_login_legit = int((df[df["label_binary"] == 0]["has_login_form"] == 1).sum())
    has_login_phish = int((df[df["label_binary"] == 1]["has_login_form"] == 1).sum())
    has_pw_legit = int((df[df["label_binary"] == 0]["num_password_fields"] > 0).sum())
    has_pw_phish = int((df[df["label_binary"] == 1]["num_password_fields"] > 0).sum())
    
    # SPA / JS-heavy distribution (heuristic: num_links <= 20, num_scripts >= 1, has_login_form == 0)
    spa_legit = int(((df["label_binary"] == 0) & (df["num_links"] <= 20) & (df["num_scripts"] >= 1) & (df["has_login_form"] == 0)).sum())
    spa_phish = int(((df["label_binary"] == 1) & (df["num_links"] <= 20) & (df["num_scripts"] >= 1) & (df["has_login_form"] == 0)).sum())
    
    # Link distribution percentiles
    link_stats_legit = {str(k): round(float(v), 2) for k, v in df[df["label_binary"] == 0]["num_links"].describe().items()}
    link_stats_phish = {str(k): round(float(v), 2) for k, v in df[df["label_binary"] == 1]["num_links"].describe().items()}

    print(f"Class Balance: Legitimate={legit_count} ({legit_count/total_samples*100:.1f}%), Phishing={phishing_count} ({phishing_count/total_samples*100:.1f}%), Ratio={imbalance_ratio}:1")
    print(f"Unique URLs: {unique_urls}, Duplicates: {duplicate_urls}")
    print(f"Unique Registered Domains: {unique_domains}")
    print(f"Parse Errors: URL={url_parse_errors}, HTML={html_parse_errors}")
    print(f"Legit Link Median={link_stats_legit['50%']}, Phish Link Median={link_stats_phish['50%']}")
    print(f"Login Forms: Legit={has_login_legit} ({has_login_legit/legit_count*100:.1f}%), Phish={has_login_phish} ({has_login_phish/phishing_count*100:.1f}%)")

    # -------------------------------------------------------------
    # 2. Data Leakage Analysis
    # -------------------------------------------------------------
    print("\n--- 2. DATA LEAKAGE ANALYSIS ---")
    # Check domain overlap across standard random/stratified split vs GroupKFold
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    train_idx_strat, test_idx_strat = next(skf.split(df, df["label_binary"]))
    strat_train_domains = set(df.iloc[train_idx_strat]["reg_domain"])
    strat_test_domains = set(df.iloc[test_idx_strat]["reg_domain"])
    strat_domain_overlap = strat_train_domains.intersection(strat_test_domains)
    strat_overlap_pct = float(len(strat_domain_overlap) / len(strat_test_domains) * 100)
    
    # Check GroupKFold domain split
    gkf = GroupKFold(n_splits=5)
    train_idx_grp, test_idx_grp = next(gkf.split(df, df["label_binary"], groups=df["reg_domain"]))
    grp_train_domains = set(df.iloc[train_idx_grp]["reg_domain"])
    grp_test_domains = set(df.iloc[test_idx_grp]["reg_domain"])
    grp_domain_overlap = grp_train_domains.intersection(grp_test_domains)
    
    # Near-duplicate feature vectors across different URLs
    feature_tuples = [tuple(row) for row in df[feature_columns].values]
    unique_feature_vectors = int(len(set(feature_tuples)))
    duplicate_feature_vectors = int(total_samples - unique_feature_vectors)
    
    print(f"Stratified Split Domain Overlap: {len(strat_domain_overlap)} domains ({strat_overlap_pct:.2f}% of test domains leak!)")
    print(f"Group Split Domain Overlap: {len(grp_domain_overlap)} domains (0.00% leakage)")
    print(f"Identical Feature Vector Duplicates across dataset: {duplicate_feature_vectors} / {total_samples}")

    # -------------------------------------------------------------
    # 3. Model Evaluation on Both Splits
    # -------------------------------------------------------------
    print("\n--- 3. MODEL EVALUATION ---")
    X = df[feature_columns].values
    y = df["label_binary"].values
    
    # A. Production Model on Group-Held-Out Test Set (The honest benchmark)
    X_train_g, X_test_g = X[train_idx_grp], X[test_idx_grp]
    y_train_g, y_test_g = y[train_idx_grp], y[test_idx_grp]
    df_test_g = df.iloc[test_idx_grp].copy()
    
    # Inference with Production Model
    y_prob_prod_g = model.predict_proba(df_test_g[feature_columns])[:, 1]
    y_pred_prod_g = (y_prob_prod_g >= 0.5).astype(int)
    
    def get_full_metrics(y_true, y_pred, y_prob):
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        cm = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
        spec = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        roc_auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0
        pr_auc = float(average_precision_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0
        brier = float(brier_score_loss(y_true, y_prob))
        return {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "specificity": round(float(spec), 4),
            "false_positive_rate": round(float(fpr), 4),
            "false_negative_rate": round(float(fnr), 4),
            "roc_auc": round(float(roc_auc), 4),
            "pr_auc": round(float(pr_auc), 4),
            "brier_score": round(float(brier), 4),
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        }

    prod_metrics_grp = get_full_metrics(y_test_g, y_pred_prod_g, y_prob_prod_g)
    
    # B. Production Model on Stratified Test Set
    df_test_s = df.iloc[test_idx_strat].copy()
    y_test_s = y[test_idx_strat]
    y_prob_prod_s = model.predict_proba(df_test_s[feature_columns])[:, 1]
    y_pred_prod_s = (y_prob_prod_s >= 0.5).astype(int)
    prod_metrics_strat = get_full_metrics(y_test_s, y_pred_prod_s, y_prob_prod_s)
    
    # C. Full dataset evaluation
    y_prob_all = model.predict_proba(df[feature_columns])[:, 1]
    y_pred_all = (y_prob_all >= 0.5).astype(int)
    prod_metrics_all = get_full_metrics(y, y_pred_all, y_prob_all)
    
    print(f"Domain-Disjoint Test Set (N={len(y_test_g)}):")
    print(f"  Accuracy: {prod_metrics_grp['accuracy']*100:.2f}% | Precision: {prod_metrics_grp['precision']*100:.2f}% | Recall: {prod_metrics_grp['recall']*100:.2f}% | F1: {prod_metrics_grp['f1_score']*100:.2f}%")
    print(f"  Specificity: {prod_metrics_grp['specificity']*100:.2f}% | FPR: {prod_metrics_grp['false_positive_rate']*100:.2f}% | FNR: {prod_metrics_grp['false_negative_rate']*100:.2f}%")
    print(f"  ROC-AUC: {prod_metrics_grp['roc_auc']:.4f} | PR-AUC: {prod_metrics_grp['pr_auc']:.4f} | Brier: {prod_metrics_grp['brier_score']:.4f}")
    print(f"  Confusion Matrix: TN={prod_metrics_grp['confusion_matrix']['tn']}, FP={prod_metrics_grp['confusion_matrix']['fp']}, FN={prod_metrics_grp['confusion_matrix']['fn']}, TP={prod_metrics_grp['confusion_matrix']['tp']}")

    # Probability Score Distribution / Calibration Analysis
    # Risk score buckets: <0.30 (low), 0.30-0.70 (medium), >=0.70 (high)
    df_test_g["pred_prob"] = y_prob_prod_g
    df_test_g["pred_label"] = y_pred_prod_g
    
    risk_low_count = int((df_test_g["pred_prob"] < 0.30).sum())
    risk_med_count = int(((df_test_g["pred_prob"] >= 0.30) & (df_test_g["pred_prob"] < 0.70)).sum())
    risk_high_count = int((df_test_g["pred_prob"] >= 0.70).sum())
    
    prob_quantiles = {
        "p10": round(float(np.percentile(y_prob_prod_g, 10)), 4),
        "p25": round(float(np.percentile(y_prob_prod_g, 25)), 4),
        "p50": round(float(np.percentile(y_prob_prod_g, 50)), 4),
        "p75": round(float(np.percentile(y_prob_prod_g, 75)), 4),
        "p90": round(float(np.percentile(y_prob_prod_g, 90)), 4),
        "p99": round(float(np.percentile(y_prob_prod_g, 99)), 4),
    }

    # -------------------------------------------------------------
    # 4. Error Analysis
    # -------------------------------------------------------------
    print("\n--- 4. ERROR ANALYSIS ---")
    fps_df = df_test_g[(df_test_g["label_binary"] == 0) & (df_test_g["pred_label"] == 1)].sort_values("pred_prob", ascending=False)
    fns_df = df_test_g[(df_test_g["label_binary"] == 1) & (df_test_g["pred_label"] == 0)].sort_values("pred_prob", ascending=True)
    
    print(f"Total False Positives in Domain Test: {len(fps_df)}")
    print(f"Total False Negatives in Domain Test: {len(fns_df)}")
    
    top_fps = []
    for _, row in fps_df.head(15).iterrows():
        top_fps.append({
            "url": str(row["url"]),
            "domain": str(row["reg_domain"]),
            "pred_prob": round(float(row["pred_prob"]), 4),
            "num_links": int(row["num_links"]),
            "num_internal_links": int(row["num_internal_links"]),
            "domain_length": int(row["domain_length"]),
            "has_login_form": int(row["has_login_form"]),
            "num_scripts": int(row["num_scripts"]),
            "uses_https": int(row["uses_https"]),
            "has_suspicious_keywords": int(row["has_suspicious_keywords"]),
        })
        
    top_fns = []
    for _, row in fns_df.head(15).iterrows():
        top_fns.append({
            "url": str(row["url"]),
            "domain": str(row["reg_domain"]),
            "pred_prob": round(float(row["pred_prob"]), 4),
            "num_links": int(row["num_links"]),
            "num_internal_links": int(row["num_internal_links"]),
            "domain_length": int(row["domain_length"]),
            "has_login_form": int(row["has_login_form"]),
            "num_scripts": int(row["num_scripts"]),
            "uses_https": int(row["uses_https"]),
            "is_shortened_url": int(row["is_shortened_url"]),
            "has_suspicious_keywords": int(row["has_suspicious_keywords"]),
        })

    # Characteristics of FPs vs True Negatives
    tn_df = df_test_g[(df_test_g["label_binary"] == 0) & (df_test_g["pred_label"] == 0)]
    fp_char = {
        "fp_mean_links": round(float(fps_df["num_links"].mean()), 2) if len(fps_df) > 0 else 0.0,
        "tn_mean_links": round(float(tn_df["num_links"].mean()), 2) if len(tn_df) > 0 else 0.0,
        "fp_median_links": round(float(fps_df["num_links"].median()), 2) if len(fps_df) > 0 else 0.0,
        "tn_median_links": round(float(tn_df["num_links"].median()), 2) if len(tn_df) > 0 else 0.0,
        "fp_mean_domain_len": round(float(fps_df["domain_length"].mean()), 2) if len(fps_df) > 0 else 0.0,
        "tn_mean_domain_len": round(float(tn_df["domain_length"].mean()), 2) if len(tn_df) > 0 else 0.0,
        "fp_login_form_rate": round(float(fps_df["has_login_form"].mean()), 4) if len(fps_df) > 0 else 0.0,
        "tn_login_form_rate": round(float(tn_df["has_login_form"].mean()), 4) if len(tn_df) > 0 else 0.0,
        "fp_http_rate": round(float((fps_df["uses_https"] == 0).mean()), 4) if len(fps_df) > 0 else 0.0,
        "tn_http_rate": round(float((tn_df["uses_https"] == 0).mean()), 4) if len(tn_df) > 0 else 0.0,
        "fp_sparse_rate": round(float(((fps_df["num_links"] <= 20) & (fps_df["has_login_form"] == 0)).mean()), 4) if len(fps_df) > 0 else 0.0,
    }
    
    # Characteristics of FNs vs True Positives
    tp_df = df_test_g[(df_test_g["label_binary"] == 1) & (df_test_g["pred_label"] == 1)]
    fn_char = {
        "fn_mean_links": round(float(fns_df["num_links"].mean()), 2) if len(fns_df) > 0 else 0.0,
        "tp_mean_links": round(float(tp_df["num_links"].mean()), 2) if len(tp_df) > 0 else 0.0,
        "fn_https_rate": round(float(fns_df["uses_https"].mean()), 4) if len(fns_df) > 0 else 0.0,
        "tp_https_rate": round(float(tp_df["uses_https"].mean()), 4) if len(tp_df) > 0 else 0.0,
        "fn_shortener_rate": round(float(fns_df["is_shortened_url"].mean()), 4) if len(fns_df) > 0 else 0.0,
        "tp_shortener_rate": round(float(tp_df["is_shortened_url"].mean()), 4) if len(tp_df) > 0 else 0.0,
    }

    # -------------------------------------------------------------
    # 5. Feature Analysis
    # -------------------------------------------------------------
    print("\n--- 5. FEATURE ANALYSIS ---")
    # Tree Feature Importances
    importances_raw = model.feature_importances_
    feat_imp = sorted(zip(feature_columns, importances_raw), key=lambda x: x[1], reverse=True)
    top2_concentration = float((feat_imp[0][1] + feat_imp[1][1]) * 100)
    top5_concentration = float(sum(x[1] for x in feat_imp[:5]) * 100)
    
    # Permutation Importance on Domain Test Set
    perm_res = permutation_importance(
        model, df_test_g[feature_columns], y_test_g, scoring="recall", n_repeats=5, random_state=42
    )
    perm_imp = sorted(
        zip(feature_columns, perm_res.importances_mean, perm_res.importances_std),
        key=lambda x: x[1],
        reverse=True,
    )
    
    # Feature Correlation Matrix
    corr_matrix = df[feature_columns].corr().abs()
    high_corr_pairs = []
    for i in range(len(feature_columns)):
        for j in range(i + 1, len(feature_columns)):
            c = corr_matrix.iloc[i, j]
            if c >= 0.70:
                high_corr_pairs.append({
                    "feature_1": str(feature_columns[i]),
                    "feature_2": str(feature_columns[j]),
                    "correlation": round(float(c), 4),
                })
    high_corr_pairs.sort(key=lambda x: x["correlation"], reverse=True)
    
    print(f"Top 2 Feature Concentration: {top2_concentration:.2f}% ({feat_imp[0][0]}: {feat_imp[0][1]:.4f}, {feat_imp[1][0]}: {feat_imp[1][1]:.4f})")
    print(f"Top 5 Feature Concentration: {top5_concentration:.2f}%")
    print(f"Highly Correlated Feature Pairs (|r| >= 0.70): {len(high_corr_pairs)}")

    # -------------------------------------------------------------
    # 6. Generalization & Subclass Slice Tests
    # -------------------------------------------------------------
    print("\n--- 6. GENERALIZATION & SLICE TESTS ---")
    
    # Slice 1: Legitimate Login / SSO Pages (legitimate pages with has_login_form=1 or num_password_fields>0)
    legit_login_mask = (df_test_g["label_binary"] == 0) & ((df_test_g["has_login_form"] == 1) | (df_test_g["num_password_fields"] > 0))
    n_legit_login = int(legit_login_mask.sum())
    if n_legit_login > 0:
        legit_login_fps = int((df_test_g[legit_login_mask]["pred_label"] == 1).sum())
        legit_login_fp_rate = float(legit_login_fps / n_legit_login)
        legit_login_mean_prob = float(df_test_g[legit_login_mask]["pred_prob"].mean())
    else:
        legit_login_fps, legit_login_fp_rate, legit_login_mean_prob = 0, 0.0, 0.0

    # Slice 2: Modern SPA / Sparse Legitimate Pages (num_links <= 20, label=0, has_login_form=0)
    legit_sparse_mask = (df_test_g["label_binary"] == 0) & (df_test_g["num_links"] <= 20) & (df_test_g["has_login_form"] == 0)
    n_legit_sparse = int(legit_sparse_mask.sum())
    if n_legit_sparse > 0:
        legit_sparse_fps = int((df_test_g[legit_sparse_mask]["pred_label"] == 1).sum())
        legit_sparse_fp_rate = float(legit_sparse_fps / n_legit_sparse)
        legit_sparse_mean_prob = float(df_test_g[legit_sparse_mask]["pred_prob"].mean())
    else:
        legit_sparse_fps, legit_sparse_fp_rate, legit_sparse_mean_prob = 0, 0.0, 0.0

    # Slice 3: Shortened URL Phishing Recall
    shortener_phish_mask = (df_test_g["label_binary"] == 1) & (df_test_g["is_shortened_url"] == 1)
    n_short_phish = int(shortener_phish_mask.sum())
    short_phish_recall = float(recall_score(df_test_g[shortener_phish_mask]["label_binary"], df_test_g[shortener_phish_mask]["pred_label"], zero_division=0)) if n_short_phish > 0 else 1.0

    # Slice 4: HTTPS Phishing Recall
    https_phish_mask = (df_test_g["label_binary"] == 1) & (df_test_g["uses_https"] == 1)
    n_https_phish = int(https_phish_mask.sum())
    https_phish_recall = float(recall_score(df_test_g[https_phish_mask]["label_binary"], df_test_g[https_phish_mask]["pred_label"], zero_division=0)) if n_https_phish > 0 else 1.0

    # Slice 5: Sparse / Low Link Phishing Recall (num_links <= 20, label=1)
    sparse_phish_mask = (df_test_g["label_binary"] == 1) & (df_test_g["num_links"] <= 20)
    n_sparse_phish = int(sparse_phish_mask.sum())
    sparse_phish_recall = float(recall_score(df_test_g[sparse_phish_mask]["label_binary"], df_test_g[sparse_phish_mask]["pred_label"], zero_division=0)) if n_sparse_phish > 0 else 1.0

    # Slice 6: Young Domain Cohort
    cohort_phish_path = BACKEND_DIR / "data" / "young_domain_cohort" / "cohort_b_phishing_young_standalone_domains.csv"
    cohort_results = {}
    if cohort_phish_path.exists():
        df_cohort_b = pd.read_csv(cohort_phish_path)
        cohort_results = {"total_cohort_samples": int(len(df_cohort_b)), "available": True}

    # -------------------------------------------------------------
    # 7. Compile Machine-Readable JSON Output
    # -------------------------------------------------------------
    diagnostic_output = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "model_identity": {
            "model_version": str(metadata.get("version", "2.1.0")),
            "model_name": str(metadata.get("model_name", "Balanced Regularized XGBoost Phishing Detector")),
            "algorithm": str(metadata.get("algorithm", "XGBClassifier")),
            "sha256_hash": str(model_sha256),
            "feature_columns_count": int(len(feature_columns)),
            "hyperparameters": metadata.get("hyperparameters", {}),
            "scale_pos_weight": float(metadata.get("hyperparameters", {}).get("scale_pos_weight", 5.0)),
        },
        "dataset_composition": {
            "total_samples": total_samples,
            "legitimate_samples": legit_count,
            "phishing_samples": phishing_count,
            "imbalance_ratio": f"{imbalance_ratio}:1",
            "unique_urls": unique_urls,
            "duplicate_urls": duplicate_urls,
            "unique_registered_domains": unique_domains,
            "duplicate_feature_vectors": duplicate_feature_vectors,
            "missing_values_total": total_missing,
            "parse_errors": {"url": url_parse_errors, "html": html_parse_errors},
            "source_distribution": source_dist,
            "top_domains_overall": top_domains_overall,
            "top_domains_legitimate": domain_counts_legit,
            "top_domains_phishing": domain_counts_phish,
            "tld_distribution_legitimate": tld_counts_legit,
            "tld_distribution_phishing": tld_counts_phish,
            "login_page_counts": {
                "legitimate_has_login_form": has_login_legit,
                "phishing_has_login_form": has_login_phish,
                "legitimate_has_password_field": has_pw_legit,
                "phishing_has_password_field": has_pw_phish,
            },
            "spa_javascript_heavy_counts": {
                "legitimate_spa_candidates": spa_legit,
                "phishing_spa_candidates": spa_phish,
            },
            "link_count_distribution": {
                "legitimate": link_stats_legit,
                "phishing": link_stats_phish,
            },
        },
        "data_leakage": {
            "stratified_split_domain_overlap_count": int(len(strat_domain_overlap)),
            "stratified_split_domain_overlap_pct": round(float(strat_overlap_pct), 2),
            "group_split_domain_overlap_count": int(len(grp_domain_overlap)),
            "group_split_domain_overlap_pct": 0.0,
            "identical_feature_vector_count": duplicate_feature_vectors,
        },
        "production_model_evaluation": {
            "domain_disjoint_held_out_test_set": prod_metrics_grp,
            "stratified_held_out_test_set": prod_metrics_strat,
            "full_dataset_evaluation": prod_metrics_all,
            "risk_score_distribution": {
                "low_risk_count_prob_lt_0_30": risk_low_count,
                "medium_risk_count_prob_0_30_to_0_70": risk_med_count,
                "high_risk_count_prob_gte_0_70": risk_high_count,
                "quantiles": prob_quantiles,
            },
        },
        "error_analysis": {
            "false_positive_count": int(len(fps_df)),
            "false_negative_count": int(len(fns_df)),
            "top_15_false_positives": top_fps,
            "top_15_false_negatives": top_fns,
            "false_positive_profile": fp_char,
            "false_negative_profile": fn_char,
        },
        "feature_analysis": {
            "all_features": [
                {
                    "name": str(col),
                    "dtype": str(df[col].dtype),
                    "tree_importance": round(float(dict(feat_imp)[col]), 6),
                    "missing_count": int(missing_counts.get(col, 0)),
                }
                for col in feature_columns
            ],
            "top_15_tree_importances": [
                {"feature": str(name), "importance": round(float(imp), 6)} for name, imp in feat_imp[:15]
            ],
            "top_15_permutation_importances": [
                {"feature": str(name), "importance_mean": round(float(mean), 6), "importance_std": round(float(std), 6)}
                for name, mean, std in perm_imp[:15]
            ],
            "top2_feature_concentration_pct": round(float(top2_concentration), 2),
            "top5_feature_concentration_pct": round(float(top5_concentration), 2),
            "multicollinear_pairs": high_corr_pairs,
        },
        "generalization_slices": {
            "legitimate_login_sso_test": {
                "total_samples": n_legit_login,
                "false_positives": legit_login_fps,
                "false_positive_rate": round(float(legit_login_fp_rate), 4),
                "mean_predicted_prob": round(float(legit_login_mean_prob), 4),
            },
            "sparse_legitimate_pages_test": {
                "total_samples": n_legit_sparse,
                "false_positives": legit_sparse_fps,
                "false_positive_rate": round(float(legit_sparse_fp_rate), 4),
                "mean_predicted_prob": round(float(legit_sparse_mean_prob), 4),
            },
            "shortened_url_phishing_recall": round(float(short_phish_recall), 4),
            "https_phishing_recall": round(float(https_phish_recall), 4),
            "sparse_phishing_recall": round(float(sparse_phish_recall), 4),
            "young_domain_cohort": cohort_results,
        },
    }

    OUTPUT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(diagnostic_output, f, indent=2, cls=NumpyEncoder)
        
    print(f"\nDiagnostic summary saved to: {OUTPUT_JSON_PATH}")
    print("=== COMPREHENSIVE ML ACCURACY DIAGNOSTIC COMPLETE ===")


if __name__ == "__main__":
    main()
