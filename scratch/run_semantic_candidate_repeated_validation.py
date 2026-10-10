"""Repeated Multi-Seed GroupShuffleSplit Validation for Semantic & Behavioral Candidate.

Evaluates across 5 diverse random seeds:
- Seed 42
- Seed 101
- Seed 777
- Seed 2024
- Seed 9999

Partition strategy: GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed)
Evaluates on identical held-out rows within each split:
1. Retrained 43-Feature Baseline (Pure Out-of-Sample for that split)
2. Semantic/Behavioral 54-Feature Candidate (Pure Out-of-Sample for that split)
3. Live Production Model v2.1.0 (Pre-trained artifact for reference)

Strict constraints:
- Zero production model modification.
- Apex domain grouping used for every split.
- 0.00% domain overlap verified for every seed.
- Production SHA-256 verified before and after.
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
logger = logging.getLogger("repeated_validation")

BACKEND_DIR = Path("backend")
MODELS_DIR = BACKEND_DIR / "ml" / "models"
PROD_MODEL_PATH = MODELS_DIR / "phishing_model.joblib"
DATA_DIR = BACKEND_DIR / "data" / "processed"
SCRATCH_DIR = Path("scratch")
SCRATCH_DIR.mkdir(parents=True, exist_ok=True)
OUT_JSON_PATH = SCRATCH_DIR / "semantic_candidate_repeated_validation.json"

SEEDS = [42, 101, 777, 2024, 9999]


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


def prepare_features(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str], List[str]]:
    df = df.copy()
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


def evaluate_split(
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
    
    # Slices
    sparse_legit_mask = (test_df["label_binary"] == 0) & (test_df["num_links"] <= 20)
    n_sparse_legit = int(sparse_legit_mask.sum())
    sparse_legit_fps = int((y_pred[sparse_legit_mask] == 1).sum()) if n_sparse_legit > 0 else 0
    sparse_legit_fpr = float(sparse_legit_fps / n_sparse_legit) if n_sparse_legit > 0 else 0.0
    
    sparse_phish_mask = (test_df["label_binary"] == 1) & (test_df["num_links"] <= 20)
    n_sparse_phish = int(sparse_phish_mask.sum())
    sparse_phish_rec = float(recall_score(y_true[sparse_phish_mask], y_pred[sparse_phish_mask], zero_division=0)) if n_sparse_phish > 0 else 1.0
    sparse_phish_tps = int((y_pred[sparse_phish_mask] == 1).sum()) if n_sparse_phish > 0 else 0
    
    https_phish_mask = (test_df["label_binary"] == 1) & (test_df["uses_https"] == 1)
    n_https_phish = int(https_phish_mask.sum())
    https_phish_rec = float(recall_score(y_true[https_phish_mask], y_pred[https_phish_mask], zero_division=0)) if n_https_phish > 0 else 1.0
    https_phish_tps = int((y_pred[https_phish_mask] == 1).sum()) if n_https_phish > 0 else 0
    
    short_phish_mask = (test_df["label_binary"] == 1) & (test_df["is_shortened_url"] == 1)
    n_short_phish = int(short_phish_mask.sum())
    short_phish_rec = float(recall_score(y_true[short_phish_mask], y_pred[short_phish_mask], zero_division=0)) if n_short_phish > 0 else 1.0
    short_phish_tps = int((y_pred[short_phish_mask] == 1).sum()) if n_short_phish > 0 else 0
    
    login_legit_mask = (test_df["label_binary"] == 0) & ((test_df["has_login_form"] == 1) | (test_df["num_password_fields"] > 0))
    n_login_legit = int(login_legit_mask.sum())
    login_legit_fps = int((y_pred[login_legit_mask] == 1).sum()) if n_login_legit > 0 else 0
    login_legit_fpr = float(login_legit_fps / n_login_legit) if n_login_legit > 0 else 0.0
    
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
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
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


def run_repeated_validation():
    logger.info("================================================================================")
    logger.info("   STARTING REPEATED MULTI-SEED VALIDATION (SEMANTIC CANDIDATE VS BASELINE)     ")
    logger.info("================================================================================")
    
    prod_sha256_before = compute_sha256(PROD_MODEL_PATH)
    logger.info("Initial Production SHA-256: %s", prod_sha256_before)
    
    raw_df = pd.read_csv(DATA_DIR / "training_dataset_expanded.csv")
    df, prod_features, semantic_features = prepare_features(raw_df)
    
    prod_model_artifact = joblib.load(PROD_MODEL_PATH)
    
    xgb_params = {
        "max_depth": 4,
        "learning_rate": 0.05,
        "n_estimators": 200,
        "colsample_bytree": 0.70,
        "subsample": 0.95,
        "reg_lambda": 1.0,
        "scale_pos_weight": 5.0,
        "eval_metric": "logloss",
        "n_jobs": -1
    }
    
    splits_results = []
    
    for seed in SEEDS:
        logger.info("\n--- Processing Seed %d ---", seed)
        gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed)
        train_idx, test_idx = next(gss.split(df, df["label_binary"], df["registered_domain"]))
        
        train_df = df.iloc[train_idx].copy()
        test_df = df.iloc[test_idx].copy()
        
        train_domains = set(train_df["registered_domain"])
        test_domains = set(test_df["registered_domain"])
        overlap = train_domains.intersection(test_domains)
        assert len(overlap) == 0, f"Domain leakage detected on seed {seed}"
        
        y_train = train_df["label_binary"].values
        y_test = test_df["label_binary"].values
        
        # 1. Baseline Model (43 features) trained on this seed
        clf_base = XGBClassifier(**xgb_params, random_state=seed)
        clf_base.fit(train_df[prod_features], y_train)
        prob_base = clf_base.predict_proba(test_df[prod_features])[:, 1]
        eval_base = evaluate_split(y_test, prob_base, test_df)
        
        # 2. Semantic Candidate Model (54 features) trained on this seed
        clf_sem = XGBClassifier(**xgb_params, random_state=seed)
        clf_sem.fit(train_df[semantic_features], y_train)
        prob_sem = clf_sem.predict_proba(test_df[semantic_features])[:, 1]
        eval_sem = evaluate_split(y_test, prob_sem, test_df)
        
        # 3. Live Production Model (v2.1.0 Artifact) evaluated on this seed
        prob_prod = prod_model_artifact.predict_proba(test_df[prod_features])[:, 1]
        eval_prod = evaluate_split(y_test, prob_prod, test_df)
        
        split_entry = {
            "seed": seed,
            "train_samples": len(train_df),
            "test_samples": len(test_df),
            "train_domains": len(train_domains),
            "test_domains": len(test_domains),
            "phishing_test_samples": int((y_test == 1).sum()),
            "legitimate_test_samples": int((y_test == 0).sum()),
            "baseline_43_features": eval_base,
            "semantic_54_features": eval_sem,
            "live_production_artifact": eval_prod,
            "delta_semantic_minus_baseline": {
                "recall_diff": round(eval_sem["recall"] - eval_base["recall"], 4),
                "accuracy_diff": round(eval_sem["accuracy"] - eval_base["accuracy"], 4),
                "precision_diff": round(eval_sem["precision"] - eval_base["precision"], 4),
                "f1_diff": round(eval_sem["f1_score"] - eval_base["f1_score"], 4),
                "fpr_diff": round(eval_sem["false_positive_rate"] - eval_base["false_positive_rate"], 4),
                "fn_count_diff": eval_sem["confusion_matrix"]["fn"] - eval_base["confusion_matrix"]["fn"],
                "fp_count_diff": eval_sem["confusion_matrix"]["fp"] - eval_base["confusion_matrix"]["fp"],
            }
        }
        splits_results.append(split_entry)
        
        logger.info(
            "Seed %d | BASELINE: Acc=%.2f%% Rec=%.2f%% (FN=%d) Prec=%.2f%% | SEMANTIC: Acc=%.2f%% Rec=%.2f%% (FN=%d) Prec=%.2f%% | RecDiff=%+.2f%% FNDiff=%+d",
            seed,
            eval_base["accuracy"] * 100,
            eval_base["recall"] * 100,
            eval_base["confusion_matrix"]["fn"],
            eval_base["precision"] * 100,
            eval_sem["accuracy"] * 100,
            eval_sem["recall"] * 100,
            eval_sem["confusion_matrix"]["fn"],
            eval_sem["precision"] * 100,
            (eval_sem["recall"] - eval_base["recall"]) * 100,
            eval_sem["confusion_matrix"]["fn"] - eval_base["confusion_matrix"]["fn"],
        )
        
    # Aggregate statistics across seeds
    def compute_stats(model_key: str) -> Dict[str, Any]:
        metrics_keys = ["accuracy", "recall", "precision", "f1_score", "specificity", "false_positive_rate", "roc_auc", "pr_auc", "brier_score"]
        stats = {}
        for k in metrics_keys:
            vals = [s[model_key][k] for s in splits_results]
            stats[k] = {
                "mean": round(float(np.mean(vals)), 4),
                "std": round(float(np.std(vals)), 4),
                "min": round(float(np.min(vals)), 4),
                "max": round(float(np.max(vals)), 4),
                "values": vals,
            }
        # Slices
        slice_keys = ["sparse_legitimate_fpr", "sparse_phishing_recall", "https_phishing_recall", "shortened_phishing_recall", "legitimate_login_fpr", "external_form_legitimate_fpr", "external_form_phishing_recall"]
        slice_stats = {}
        for sk in slice_keys:
            vals = [s[model_key]["slices"][sk] for s in splits_results]
            slice_stats[sk] = {
                "mean": round(float(np.mean(vals)), 4),
                "std": round(float(np.std(vals)), 4),
                "values": vals,
            }
        stats["slices"] = slice_stats
        
        # FN and FP totals
        fn_vals = [s[model_key]["confusion_matrix"]["fn"] for s in splits_results]
        fp_vals = [s[model_key]["confusion_matrix"]["fp"] for s in splits_results]
        stats["confusion_totals"] = {
            "fn_values": fn_vals,
            "fn_mean": round(float(np.mean(fn_vals)), 2),
            "fp_values": fp_vals,
            "fp_mean": round(float(np.mean(fp_vals)), 2),
        }
        return stats

    baseline_aggregate = compute_stats("baseline_43_features")
    semantic_aggregate = compute_stats("semantic_54_features")
    prod_artifact_aggregate = compute_stats("live_production_artifact")
    
    # Consistency analysis
    rec_diffs = [s["delta_semantic_minus_baseline"]["recall_diff"] for s in splits_results]
    acc_diffs = [s["delta_semantic_minus_baseline"]["accuracy_diff"] for s in splits_results]
    prec_diffs = [s["delta_semantic_minus_baseline"]["precision_diff"] for s in splits_results]
    f1_diffs = [s["delta_semantic_minus_baseline"]["f1_diff"] for s in splits_results]
    fn_diffs = [s["delta_semantic_minus_baseline"]["fn_count_diff"] for s in splits_results]
    
    semantic_wins_recall = sum(1 for d in rec_diffs if d > 0)
    semantic_ties_recall = sum(1 for d in rec_diffs if d == 0)
    semantic_losses_recall = sum(1 for d in rec_diffs if d < 0)
    
    semantic_wins_acc = sum(1 for d in acc_diffs if d > 0)
    semantic_ties_acc = sum(1 for d in acc_diffs if d == 0)
    semantic_losses_acc = sum(1 for d in acc_diffs if d < 0)
    
    consistency_summary = {
        "seeds_evaluated": SEEDS,
        "semantic_recall_vs_baseline": {
            "wins": semantic_wins_recall,
            "ties": semantic_ties_recall,
            "losses": semantic_losses_recall,
            "recall_diff_mean": round(float(np.mean(rec_diffs)), 4),
            "recall_diff_values": rec_diffs,
            "fn_diff_values": fn_diffs,
        },
        "semantic_accuracy_vs_baseline": {
            "wins": semantic_wins_acc,
            "ties": semantic_ties_acc,
            "losses": semantic_losses_acc,
            "acc_diff_mean": round(float(np.mean(acc_diffs)), 4),
            "acc_diff_values": acc_diffs,
        },
        "semantic_precision_vs_baseline": {
            "prec_diff_mean": round(float(np.mean(prec_diffs)), 4),
            "prec_diff_values": prec_diffs,
        },
        "meets_94_percent_recall_all_seeds": {
            "baseline_meets_all": all(s["baseline_43_features"]["recall"] >= 0.94 for s in splits_results),
            "semantic_meets_all": all(s["semantic_54_features"]["recall"] >= 0.94 for s in splits_results),
        }
    }
    
    final_report = {
        "experiment_title": "Semantic Candidate Repeated Multi-Seed Domain-Grouped Validation",
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "methodology": "Repeated GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed) across 5 seeds",
        "seeds": SEEDS,
        "production_model_sha256": prod_sha256_before,
        "consistency_summary": consistency_summary,
        "aggregate_metrics": {
            "baseline_43_features": baseline_aggregate,
            "semantic_54_features": semantic_aggregate,
            "live_production_artifact": prod_artifact_aggregate,
        },
        "individual_split_results": splits_results,
    }
    
    with open(OUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2, cls=NumpyEncoder)
        
    prod_sha256_after = compute_sha256(PROD_MODEL_PATH)
    assert prod_sha256_before == prod_sha256_after, "CRITICAL ERROR: Production model SHA-256 changed!"
    logger.info("Verified: Production Model SHA-256 remains 100%% unchanged (%s)", prod_sha256_after)
    logger.info("Repeated validation report written to %s", OUT_JSON_PATH)
    
    return final_report


if __name__ == "__main__":
    run_repeated_validation()
