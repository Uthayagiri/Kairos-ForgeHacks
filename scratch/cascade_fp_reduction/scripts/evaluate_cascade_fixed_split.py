"""Phase 7 & 8: Fixed-Split Evaluation of Cascade Candidates (A, B, C, D, E).

Evaluates all cascade candidates on the exact held-out fixed test partition (N=1,799).
Computes all primary metrics and 14 fine-grained evaluation slices.
Generates scratch/cascade_fp_reduction/reports/FIXED_SPLIT_RESULTS.md.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score, recall_score, precision_score, f1_score,
    roc_auc_score, average_precision_score, confusion_matrix, brier_score_loss
)

DATA_PATH = "backend/data/processed/training_dataset_expanded.csv"
PROD_MODEL_PATH = "backend/ml/models/phishing_model.joblib"
MODELS_DIR = "scratch/cascade_fp_reduction/models"
REPORTS_DIR = "scratch/cascade_fp_reduction/reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

PROD_FEATURES = [
    "url_length", "domain_length", "path_length", "num_dots", "num_hyphens",
    "num_underscores", "num_slashes", "num_digits", "num_special_chars",
    "num_subdomains", "num_query_params", "path_depth", "has_at_symbol",
    "has_ip_address", "uses_https", "has_port", "has_url_encoding",
    "has_suspicious_tld", "has_suspicious_keywords", "has_double_slash_redirect",
    "is_shortened_url", "url_parse_error", "num_forms", "num_input_fields",
    "num_password_fields", "has_login_form", "num_forms_with_external_action",
    "has_form_action_empty_or_javascript", "num_links", "num_internal_links",
    "num_external_links", "external_link_ratio", "num_links_with_mismatched_text",
    "num_scripts", "num_iframes", "has_hidden_iframe", "has_suspicious_js_patterns",
    "num_meta_refresh_redirects", "title_length", "has_favicon", "num_images",
    "text_to_html_ratio", "html_parse_error"
]

STRONG_PHISHING_SIGNALS = [
    "has_ip_address", "has_at_symbol", "has_double_slash_redirect",
    "has_suspicious_tld", "has_suspicious_keywords", "has_url_encoding",
    "has_form_action_empty_or_javascript", "has_hidden_iframe",
    "has_suspicious_js_patterns"
]

def compute_compound_evidence(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    strong_score = np.zeros(len(df), dtype=int)
    for sig in STRONG_PHISHING_SIGNALS:
        if sig in df.columns:
            strong_score += (df[sig] > 0).astype(int)
    if "num_forms_with_external_action" in df.columns:
        strong_score += (df["num_forms_with_external_action"] > 0).astype(int)
    if "num_links_with_mismatched_text" in df.columns:
        strong_score += (df["num_links_with_mismatched_text"] > 0).astype(int)
    if "num_meta_refresh_redirects" in df.columns:
        strong_score += (df["num_meta_refresh_redirects"] > 0).astype(int)
        
    df["strong_phishing_evidence_score"] = strong_score
    df["has_strong_phishing_veto"] = (strong_score >= 1).astype(int)
    
    is_spa = (
        (df["num_links"] <= 20) &
        (df["num_forms"] == 0) &
        (df["num_scripts"] >= 1) &
        (df["text_to_html_ratio"] <= 0.10) &
        (df["has_login_form"] == 0)
    ).astype(int)
    df["is_spa_shell_pattern"] = is_spa
    
    return df

def evaluate_predictions(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray, df: pd.DataFrame) -> Dict[str, Any]:
    acc = accuracy_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred, zero_division=0)
    prec = precision_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    roc_auc = roc_auc_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else 0.0
    pr_auc = average_precision_score(y_true, y_prob) if len(np.unique(y_true)) > 1 else 0.0
    
    # 14 Fine-grained slices
    def slice_metrics(mask, is_pos=True):
        if mask.sum() == 0:
            return 0.0, 0, 0
        sub_true = y_true[mask]
        sub_pred = y_pred[mask]
        if is_pos:
            tps = int(((sub_true == 1) & (sub_pred == 1)).sum())
            tot = int((sub_true == 1).sum())
            return (tps / tot) if tot > 0 else 0.0, tps, tot
        else:
            fps = int(((sub_true == 0) & (sub_pred == 1)).sum())
            tot = int((sub_true == 0).sum())
            return (fps / tot) if tot > 0 else 0.0, fps, tot

    # Slice masks
    sparse_m = (df["num_links"] <= 20).values
    https_m = (df["uses_https"] == 1).values
    zero_intern_m = (df["num_internal_links"] == 0).values
    login_m = (df["has_login_form"] == 1).values
    ext_form_m = (df["num_forms_with_external_action"] > 0).values
    js_m = (df["num_scripts"] >= 2).values
    gov_m = (df["url"].str.contains(r"\.gov|\.edu", regex=True, case=False)).values
    cloud_m = (df["url"].str.contains(r"azure|cloud\.microsoft|aws|appspot|firebase", regex=True, case=False)).values
    long_url_m = (df["url_length"] >= 75).values
    short_url_m = (df["url_length"] <= 35).values
    redir_m = (df["has_double_slash_redirect"] == 1).values

    slices = {
        "sparse_legitimate_fpr": slice_metrics(sparse_m & (y_true == 0), is_pos=False)[0],
        "sparse_legitimate_fps": slice_metrics(sparse_m & (y_true == 0), is_pos=False)[1],
        "sparse_legitimate_total": slice_metrics(sparse_m & (y_true == 0), is_pos=False)[2],
        
        "sparse_phishing_recall": slice_metrics(sparse_m & (y_true == 1), is_pos=True)[0],
        "sparse_phishing_tps": slice_metrics(sparse_m & (y_true == 1), is_pos=True)[1],
        "sparse_phishing_total": slice_metrics(sparse_m & (y_true == 1), is_pos=True)[2],
        
        "https_phishing_recall": slice_metrics(https_m & (y_true == 1), is_pos=True)[0],
        "https_phishing_tps": slice_metrics(https_m & (y_true == 1), is_pos=True)[1],
        "https_phishing_total": slice_metrics(https_m & (y_true == 1), is_pos=True)[2],
        
        "https_legitimate_fpr": slice_metrics(https_m & (y_true == 0), is_pos=False)[0],
        "https_legitimate_fps": slice_metrics(https_m & (y_true == 0), is_pos=False)[1],
        "https_legitimate_total": slice_metrics(https_m & (y_true == 0), is_pos=False)[2],
        
        "zero_internal_links_legit_fpr": slice_metrics(zero_intern_m & (y_true == 0), is_pos=False)[0],
        "zero_internal_links_phish_recall": slice_metrics(zero_intern_m & (y_true == 1), is_pos=True)[0],
        
        "login_legitimate_fpr": slice_metrics(login_m & (y_true == 0), is_pos=False)[0],
        "login_legitimate_fps": slice_metrics(login_m & (y_true == 0), is_pos=False)[1],
        "login_legitimate_total": slice_metrics(login_m & (y_true == 0), is_pos=False)[2],
        
        "ext_form_legitimate_fpr": slice_metrics(ext_form_m & (y_true == 0), is_pos=False)[0],
        "ext_form_legitimate_fps": slice_metrics(ext_form_m & (y_true == 0), is_pos=False)[1],
        "ext_form_legitimate_total": slice_metrics(ext_form_m & (y_true == 0), is_pos=False)[2],
        
        "ext_form_phishing_recall": slice_metrics(ext_form_m & (y_true == 1), is_pos=True)[0],
        "ext_form_phishing_tps": slice_metrics(ext_form_m & (y_true == 1), is_pos=True)[1],
        "ext_form_phishing_total": slice_metrics(ext_form_m & (y_true == 1), is_pos=True)[2],
        
        "js_rendered_legit_fpr": slice_metrics(js_m & (y_true == 0), is_pos=False)[0],
        "gov_institutional_legit_fpr": slice_metrics(gov_m & (y_true == 0), is_pos=False)[0],
        "cloud_hosted_legit_fpr": slice_metrics(cloud_m & (y_true == 0), is_pos=False)[0],
        
        "long_url_phish_recall": slice_metrics(long_url_m & (y_true == 1), is_pos=True)[0],
        "short_url_phish_recall": slice_metrics(short_url_m & (y_true == 1), is_pos=True)[0],
        "redirect_page_recall": slice_metrics(redir_m & (y_true == 1), is_pos=True)[0],
    }
    
    return {
        "accuracy": round(float(acc), 4),
        "recall": round(float(rec), 4),
        "precision": round(float(prec), 4),
        "f1_score": round(float(f1), 4),
        "specificity": round(float(spec), 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "roc_auc": round(float(roc_auc), 4),
        "pr_auc": round(float(pr_auc), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "slices": {k: (round(float(v), 4) if isinstance(v, float) else v) for k, v in slices.items()}
    }

def run_fixed_split_evaluation():
    print("=" * 80)
    print("PHASE 8: FIXED-SPLIT CASCADE EVALUATION (N=1,799, Seed 42)")
    print("=" * 80)
    
    df = pd.read_csv(DATA_PATH)
    df = compute_compound_evidence(df)
    
    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    train_idx, test_idx = next(gss.split(df, df["label_binary"], df["registered_domain"]))
    test_df = df.iloc[test_idx].copy().reset_index(drop=True)
    
    y_test = test_df["label_binary"].values
    
    prod_model = joblib.load(PROD_MODEL_PATH)
    stage2_lr = joblib.load(os.path.join(MODELS_DIR, "stage2_lr_verifier.joblib"))
    stage2_tree = joblib.load(os.path.join(MODELS_DIR, "stage2_tree_verifier.joblib"))
    with open(os.path.join(MODELS_DIR, "stage2_feature_names.json"), "r", encoding="utf-8") as f:
        stage2_features = json.load(f)
        
    # Generate Stage 1 scores
    s1_scores = prod_model.predict_proba(test_df[PROD_FEATURES])[:, 1]
    test_df["stage1_score"] = s1_scores
    
    # Generate Stage 2 scores
    X_test_s2 = test_df[stage2_features].values
    s2_lr_scores = stage2_lr.predict_proba(X_test_s2)[:, 1]
    s2_tree_scores = stage2_tree.predict_proba(X_test_s2)[:, 1]
    test_df["stage2_lr_score"] = s2_lr_scores
    test_df["stage2_tree_score"] = s2_tree_scores
    
    # Define Candidate Decision Rules:
    
    # Candidate A: Baseline Production Stage 1 only
    pred_a = (s1_scores >= 0.50).astype(int)
    prob_a = s1_scores
    
    # Candidate B: Production Stage 1 + Stage 2 on all S1 >= 0.50 (no veto)
    # If S1 >= 0.50, defer to Stage 2 verifier (threshold 0.50). If S2 < 0.50 -> de-escalate to 0.
    pred_b = np.zeros(len(test_df), dtype=int)
    prob_b = s1_scores.copy()
    for i in range(len(test_df)):
        if s1_scores[i] >= 0.50:
            pred_b[i] = 1 if s2_lr_scores[i] >= 0.50 else 0
            prob_b[i] = s2_lr_scores[i]
            
    # Candidate C: Stage 1 + Stage 2 on borderline scores ONLY (0.35 <= S1 <= 0.70)
    # High confidence S1 > 0.70 is preserved as Phishing. Low confidence S1 < 0.35 is Safe.
    pred_c = np.zeros(len(test_df), dtype=int)
    prob_c = s1_scores.copy()
    for i in range(len(test_df)):
        if s1_scores[i] > 0.70:
            pred_c[i] = 1
        elif 0.35 <= s1_scores[i] <= 0.70:
            pred_c[i] = 1 if s2_lr_scores[i] >= 0.50 else 0
            prob_c[i] = s2_lr_scores[i]
        else:
            pred_c[i] = 0
            
    # Candidate D: Stage 1 + Borderline Stage 2 + Strict Phishing-Evidence VETO
    # If S1 > 0.70 -> 1.
    # If 0.35 <= S1 <= 0.70:
    #   If has_strong_phishing_veto == 1 -> STRICT VETO (cannot de-escalate -> 1)
    #   Else -> defer to Stage 2
    # If S1 < 0.35 -> 0
    pred_d = np.zeros(len(test_df), dtype=int)
    prob_d = s1_scores.copy()
    for i in range(len(test_df)):
        if s1_scores[i] > 0.70:
            pred_d[i] = 1
        elif 0.35 <= s1_scores[i] <= 0.70:
            if test_df["has_strong_phishing_veto"].iloc[i] == 1:
                pred_d[i] = 1  # Veto prevents de-escalation
            else:
                pred_d[i] = 1 if s2_lr_scores[i] >= 0.50 else 0
                prob_d[i] = s2_lr_scores[i]
        else:
            pred_d[i] = 0
            
    # Candidate E: Conservative Risk Banding Cascade
    # High Risk: S1 > 0.75 or strong veto -> Block (1)
    # Medium Risk: 0.35 <= S1 <= 0.75 -> Warn / Verify (1 in conservative posture, with SPA de-escalation only when 0 evidence)
    # Low Risk: S1 < 0.35 -> Safe (0)
    pred_e = np.zeros(len(test_df), dtype=int)
    prob_e = s1_scores.copy()
    for i in range(len(test_df)):
        if s1_scores[i] >= 0.75 or test_df["has_strong_phishing_veto"].iloc[i] == 1:
            pred_e[i] = 1
        elif 0.35 <= s1_scores[i] < 0.75:
            # Only de-escalate if verified SPA pattern with zero strong evidence
            if test_df["is_spa_shell_pattern"].iloc[i] == 1 and test_df["strong_phishing_evidence_score"].iloc[i] == 0:
                pred_e[i] = 0
                prob_e[i] = 0.20
            else:
                pred_e[i] = 1 if s2_lr_scores[i] >= 0.50 else 0
                prob_e[i] = s2_lr_scores[i]
        else:
            pred_e[i] = 0

    results = {
        "candidate_a": evaluate_predictions(y_test, pred_a, prob_a, test_df),
        "candidate_b": evaluate_predictions(y_test, pred_b, prob_b, test_df),
        "candidate_c": evaluate_predictions(y_test, pred_c, prob_c, test_df),
        "candidate_d": evaluate_predictions(y_test, pred_d, prob_d, test_df),
        "candidate_e": evaluate_predictions(y_test, pred_e, prob_e, test_df),
    }
    
    print("\n--- FIXED SPLIT CANDIDATE COMPARISON ---")
    header = f"{'Candidate':<20} | {'Accuracy':<10} | {'Recall':<10} | {'Precision':<10} | {'F1':<10} | {'FPR':<10} | {'Sparse FPR':<12} | {'FP':<5} | {'FN':<5}"
    print(header)
    print("-" * len(header))
    for k, v in results.items():
        print(f"{k:<20} | {v['accuracy']*100:<9.2f}% | {v['recall']*100:<9.2f}% | {v['precision']*100:<9.2f}% | {v['f1_score']*100:<9.2f}% | {v['false_positive_rate']*100:<9.2f}% | {v['slices']['sparse_legitimate_fpr']*100:<11.2f}% | {v['confusion_matrix']['fp']:<5} | {v['confusion_matrix']['fn']:<5}")
        
    # Generate FIXED_SPLIT_RESULTS.md
    md_lines = [
        "# Fixed-Split Cascade Benchmark Results",
        "**Task ID**: `EXP-13-HIGH-RECALL-CASCADE-FP-REDUCTION-IMPLEMENTATION`  ",
        "**Date**: `2026-09-16`  ",
        "**Test Partition**: $N=1,799$ samples ($1,402$ Legitimate, $397$ Phishing across $631$ domain-disjoint apex domains)  ",
        "",
        "## 1. Candidate Architectural Configurations",
        "- **Candidate A**: Production Stage 1 Only (Baseline, $\\tau = 0.50$).",
        "- **Candidate B**: Production Stage 1 + Stage 2 Verifier on all $S_1 \\ge 0.50$ (No Veto).",
        "- **Candidate C**: Production Stage 1 + Stage 2 Verifier on Borderline Scores ($0.35 \\le S_1 \\le 0.70$).",
        "- **Candidate D**: Production Stage 1 + Borderline Stage 2 + Strict Multi-Indicator Phishing Veto.",
        "- **Candidate E**: Conservative Risk-Banding Cascade (High/Medium/Low with SPA context de-escalation).",
        "",
        "## 2. Benchmark Metric Table ($N=1,799$, Seed 42)",
        "",
        "| Metric | Candidate A (Baseline) | Candidate B (No Veto) | Candidate C (Borderline) | Candidate D (Strict Veto) | Candidate E (Risk Banding) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: |"
    ]
    
    metrics_to_show = [
        ("Accuracy", "accuracy", "%"),
        ("Phishing Recall (>=94% req.)", "recall", "%"),
        ("Precision", "precision", "%"),
        ("F1-Score", "f1_score", "%"),
        ("Specificity", "specificity", "%"),
        ("False Positive Rate (FPR)", "false_positive_rate", "%"),
        ("False Negative Rate (FNR)", "false_negative_rate", "%"),
        ("ROC-AUC", "roc_auc", ""),
        ("PR-AUC", "pr_auc", ""),
        ("False Positives (FP)", "confusion_matrix.fp", "count"),
        ("False Negatives (FN)", "confusion_matrix.fn", "count"),
        ("Sparse Legit FPR", "slices.sparse_legitimate_fpr", "%"),
        ("Sparse Phishing Recall", "slices.sparse_phishing_recall", "%"),
        ("HTTPS Phishing Recall", "slices.https_phishing_recall", "%"),
        ("HTTPS Legit FPR", "slices.https_legitimate_fpr", "%"),
        ("Zero Internal Links Phish Recall", "slices.zero_internal_links_phish_recall", "%"),
        ("Zero Internal Links Legit FPR", "slices.zero_internal_links_legit_fpr", "%"),
        ("Legit Login/SSO FPR", "slices.login_legitimate_fpr", "%"),
        ("External Form Legit FPR", "slices.ext_form_legitimate_fpr", "%"),
        ("External Form Phish Recall", "slices.ext_form_phishing_recall", "%"),
        ("JS-Rendered Legit FPR", "slices.js_rendered_legit_fpr", "%"),
        ("Gov/Institutional Legit FPR", "slices.gov_institutional_legit_fpr", "%"),
        ("Cloud-Hosted Legit FPR", "slices.cloud_hosted_legit_fpr", "%"),
        ("Long URL Phish Recall", "slices.long_url_phish_recall", "%"),
        ("Short URL Phish Recall", "slices.short_url_phish_recall", "%"),
        ("Redirect Page Recall", "slices.redirect_page_recall", "%")
    ]
    
    def get_val(res_dict, key_path):
        parts = key_path.split(".")
        cur = res_dict
        for p in parts:
            cur = cur[p]
        return cur

    for label, key, unit in metrics_to_show:
        vals = []
        for c in ["candidate_a", "candidate_b", "candidate_c", "candidate_d", "candidate_e"]:
            v = get_val(results[c], key)
            if unit == "%":
                vals.append(f"{v*100:.2f}%")
            elif unit == "count":
                vals.append(f"{v}")
            else:
                vals.append(f"{v:.4f}")
        md_lines.append(f"| **{label}** | " + " | ".join(vals) + " |")
        
    out_md_path = os.path.join(REPORTS_DIR, "FIXED_SPLIT_RESULTS.md")
    with open(out_md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines) + "\n")
        
    with open(os.path.join(REPORTS_DIR, "fixed_split_results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        
    print(f"\nFixed split benchmark report generated at {out_md_path}")
    return results

if __name__ == "__main__":
    run_fixed_split_evaluation()
