"""Phase 9: Repeated Domain-Disjoint 5-Seed Validation.

Evaluates all cascade candidates across seeds [42, 101, 777, 2024, 9999].
Computes stability, mean, std, worst-seed recall, worst-seed FPR.
Generates scratch/cascade_fp_reduction/reports/REPEATED_VALIDATION.md and repeated_validation_results.json.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List
from sklearn.model_selection import GroupShuffleSplit, GroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, recall_score, precision_score, f1_score, confusion_matrix, roc_auc_score, average_precision_score
from xgboost import XGBClassifier

DATA_PATH = "backend/data/processed/training_dataset_expanded.csv"
PROD_MODEL_PATH = "backend/ml/models/phishing_model.joblib"
REPORTS_DIR = "scratch/cascade_fp_reduction/reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

SEEDS = [42, 101, 777, 2024, 9999]

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

STAGE2_FEATURES = [
    "stage1_score",
    "url_length", "domain_length", "path_length", "num_dots", "num_hyphens",
    "num_subdomains", "num_query_params", "path_depth",
    "has_at_symbol", "has_ip_address", "has_port", "has_url_encoding",
    "has_suspicious_tld", "has_suspicious_keywords", "has_double_slash_redirect", "is_shortened_url",
    "num_forms", "num_input_fields", "num_password_fields", "has_login_form",
    "num_forms_with_external_action", "has_form_action_empty_or_javascript",
    "num_links", "num_internal_links", "num_external_links", "external_link_ratio",
    "num_links_with_mismatched_text", "num_scripts", "num_iframes", "has_hidden_iframe",
    "has_suspicious_js_patterns", "num_meta_refresh_redirects", "title_length",
    "has_favicon", "num_images", "text_to_html_ratio",
    "strong_phishing_evidence_score", "is_spa_shell_pattern"
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

def eval_metrics(y_true: np.ndarray, y_pred: np.ndarray, df: pd.DataFrame) -> Dict[str, Any]:
    acc = accuracy_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred, zero_division=0)
    prec = precision_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (tn + fp) if (tn + fp) > 0 else 0.0
    
    sparse_m = ((df["num_links"] <= 20) & (y_true == 0)).values
    sparse_fps = int(((y_true[sparse_m] == 0) & (y_pred[sparse_m] == 1)).sum()) if sparse_m.sum() > 0 else 0
    sparse_tot = int(sparse_m.sum())
    sparse_fpr = (sparse_fps / sparse_tot) if sparse_tot > 0 else 0.0
    
    return {
        "accuracy": round(float(acc), 4),
        "recall": round(float(rec), 4),
        "precision": round(float(prec), 4),
        "f1": round(float(f1), 4),
        "fpr": round(float(fpr), 4),
        "sparse_fpr": round(float(sparse_fpr), 4),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "tn": int(tn),
    }

def run_repeated_validation():
    print("=" * 80)
    print("PHASE 9: REPEATED 5-SEED DOMAIN-DISJOINT VALIDATION")
    print("=" * 80)
    
    df = pd.read_csv(DATA_PATH)
    df = compute_compound_evidence(df)
    
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
    
    seed_results = []
    
    for seed in SEEDS:
        print(f"\nEvaluating Seed {seed}...")
        gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed)
        tr_i, te_i = next(gss.split(df, df["label_binary"], df["registered_domain"]))
        
        tr_df = df.iloc[tr_i].copy().reset_index(drop=True)
        te_df = df.iloc[te_i].copy().reset_index(drop=True)
        
        # Verify 0 domain leakage
        assert len(set(tr_df["registered_domain"]).intersection(set(te_df["registered_domain"]))) == 0, f"Leakage seed {seed}!"
        
        # Train Stage 1 on this seed's training partition
        s1_clf = XGBClassifier(**xgb_params, random_state=seed)
        s1_clf.fit(tr_df[PROD_FEATURES], tr_df["label_binary"].values)
        
        # Generate OOF Stage 1 predictions on tr_df for Stage 2 training
        gkf_s = GroupKFold(n_splits=5)
        oof_s1 = np.zeros(len(tr_df), dtype=float)
        for f_tr_idx, f_val_idx in gkf_s.split(tr_df, tr_df["label_binary"], tr_df["registered_domain"]):
            m_k = XGBClassifier(**xgb_params, random_state=seed)
            m_k.fit(tr_df.iloc[f_tr_idx][PROD_FEATURES], tr_df.iloc[f_tr_idx]["label_binary"].values)
            oof_s1[f_val_idx] = m_k.predict_proba(tr_df.iloc[f_val_idx][PROD_FEATURES])[:, 1]
            
        tr_df["stage1_score"] = oof_s1
        
        # Train Stage 2 on OOF predictions >= 0.35
        s2_mask = (tr_df["stage1_score"] >= 0.35)
        s2_subset = tr_df[s2_mask]
        s2_clf = LogisticRegression(C=0.10, penalty="l2", solver="lbfgs", max_iter=1000, random_state=seed)
        s2_clf.fit(s2_subset[STAGE2_FEATURES].values, s2_subset["label_binary"].values)
        
        # Predict on Held-Out Test Set
        s1_test_scores = s1_clf.predict_proba(te_df[PROD_FEATURES])[:, 1]
        te_df["stage1_score"] = s1_test_scores
        s2_test_scores = s2_clf.predict_proba(te_df[STAGE2_FEATURES].values)[:, 1]
        te_df["stage2_score"] = s2_test_scores
        
        y_test = te_df["label_binary"].values
        
        # Candidate A: Baseline Stage 1
        p_a = (s1_test_scores >= 0.50).astype(int)
        
        # Candidate B: Stage 1 + Stage 2 on all S1 >= 0.50
        p_b = np.zeros(len(te_df), dtype=int)
        for i in range(len(te_df)):
            if s1_test_scores[i] >= 0.50:
                p_b[i] = 1 if s2_test_scores[i] >= 0.50 else 0
                
        # Candidate C: Stage 1 + Borderline Stage 2 (0.35 <= S1 <= 0.70)
        p_c = np.zeros(len(te_df), dtype=int)
        for i in range(len(te_df)):
            if s1_test_scores[i] > 0.70:
                p_c[i] = 1
            elif 0.35 <= s1_test_scores[i] <= 0.70:
                p_c[i] = 1 if s2_test_scores[i] >= 0.50 else 0
            else:
                p_c[i] = 0
                
        # Candidate D: Stage 1 + Borderline Stage 2 + Strict Phishing Veto
        p_d = np.zeros(len(te_df), dtype=int)
        for i in range(len(te_df)):
            if s1_test_scores[i] > 0.70:
                p_d[i] = 1
            elif 0.35 <= s1_test_scores[i] <= 0.70:
                if te_df["has_strong_phishing_veto"].iloc[i] == 1:
                    p_d[i] = 1
                else:
                    p_d[i] = 1 if s2_test_scores[i] >= 0.50 else 0
            else:
                p_d[i] = 0
                
        # Candidate E: Conservative Cascade (High-Recall S1 threshold 0.40 + Vetoed Stage 2)
        p_e = np.zeros(len(te_df), dtype=int)
        for i in range(len(te_df)):
            if s1_test_scores[i] > 0.65 or te_df["has_strong_phishing_veto"].iloc[i] == 1:
                p_e[i] = 1
            elif 0.35 <= s1_test_scores[i] <= 0.65:
                if te_df["is_spa_shell_pattern"].iloc[i] == 1 and te_df["strong_phishing_evidence_score"].iloc[i] == 0:
                    p_e[i] = 0
                else:
                    p_e[i] = 1 if s2_test_scores[i] >= 0.50 else 0
            else:
                p_e[i] = 0

        ev_a = eval_metrics(y_test, p_a, te_df)
        ev_b = eval_metrics(y_test, p_b, te_df)
        ev_c = eval_metrics(y_test, p_c, te_df)
        ev_d = eval_metrics(y_test, p_d, te_df)
        ev_e = eval_metrics(y_test, p_e, te_df)
        
        seed_record = {
            "seed": seed,
            "candidate_a": ev_a,
            "candidate_b": ev_b,
            "candidate_c": ev_c,
            "candidate_d": ev_d,
            "candidate_e": ev_e
        }
        seed_results.append(seed_record)
        print(f"  Cand A: Rec={ev_a['recall']*100:.2f}% | FPR={ev_a['fpr']*100:.2f}% | SparseFPR={ev_a['sparse_fpr']*100:.2f}% | FN={ev_a['fn']} | FP={ev_a['fp']}")
        print(f"  Cand B: Rec={ev_b['recall']*100:.2f}% | FPR={ev_b['fpr']*100:.2f}% | SparseFPR={ev_b['sparse_fpr']*100:.2f}% | FN={ev_b['fn']} | FP={ev_b['fp']}")
        print(f"  Cand C: Rec={ev_c['recall']*100:.2f}% | FPR={ev_c['fpr']*100:.2f}% | SparseFPR={ev_c['sparse_fpr']*100:.2f}% | FN={ev_c['fn']} | FP={ev_c['fp']}")
        print(f"  Cand D: Rec={ev_d['recall']*100:.2f}% | FPR={ev_d['fpr']*100:.2f}% | SparseFPR={ev_d['sparse_fpr']*100:.2f}% | FN={ev_d['fn']} | FP={ev_d['fp']}")
        print(f"  Cand E: Rec={ev_e['recall']*100:.2f}% | FPR={ev_e['fpr']*100:.2f}% | SparseFPR={ev_e['sparse_fpr']*100:.2f}% | FN={ev_e['fn']} | FP={ev_e['fp']}")

    # Aggregate 5-seed statistics
    print("\n" + "=" * 80)
    print("5-SEED AGGREGATE SUMMARY")
    print("=" * 80)
    agg_summary = {}
    for cand in ["candidate_a", "candidate_b", "candidate_c", "candidate_d", "candidate_e"]:
        recs = [s[cand]["recall"] * 100 for s in seed_results]
        fprs = [s[cand]["fpr"] * 100 for s in seed_results]
        sparse_fprs = [s[cand]["sparse_fpr"] * 100 for s in seed_results]
        precs = [s[cand]["precision"] * 100 for s in seed_results]
        accs = [s[cand]["accuracy"] * 100 for s in seed_results]
        fns = [s[cand]["fn"] for s in seed_results]
        fps = [s[cand]["fp"] for s in seed_results]
        
        agg_summary[cand] = {
            "recall_mean": round(float(np.mean(recs)), 2),
            "recall_std": round(float(np.std(recs)), 2),
            "recall_min": round(float(np.min(recs)), 2),
            "recall_max": round(float(np.max(recs)), 2),
            "worst_seed_recall": round(float(np.min(recs)), 2),
            "fpr_mean": round(float(np.mean(fprs)), 2),
            "fpr_std": round(float(np.std(fprs)), 2),
            "worst_seed_fpr": round(float(np.max(fprs)), 2),
            "sparse_fpr_mean": round(float(np.mean(sparse_fprs)), 2),
            "precision_mean": round(float(np.mean(precs)), 2),
            "accuracy_mean": round(float(np.mean(accs)), 2),
            "total_fn": int(sum(fns)),
            "total_fp": int(sum(fps))
        }
        print(f"[{cand.upper()}]")
        print(f"  Recall (5 seeds):     {recs} -> Mean: {agg_summary[cand]['recall_mean']}% +/- {agg_summary[cand]['recall_std']}% (Worst: {agg_summary[cand]['worst_seed_recall']}%)")
        print(f"  FPR (5 seeds):        {fprs} -> Mean: {agg_summary[cand]['fpr_mean']}% +/- {agg_summary[cand]['fpr_std']}% (Worst: {agg_summary[cand]['worst_seed_fpr']}%)")
        print(f"  Sparse FPR (5 seeds): {sparse_fprs} -> Mean: {agg_summary[cand]['sparse_fpr_mean']}%")
        print(f"  Total FNs: {agg_summary[cand]['total_fn']} | Total FPs: {agg_summary[cand]['total_fp']}")
        print()
        
    out_json = {
        "seeds": SEEDS,
        "per_seed_results": seed_results,
        "aggregate_summary": agg_summary
    }
    with open(os.path.join(REPORTS_DIR, "repeated_validation_results.json"), "w", encoding="utf-8") as f:
        json.dump(out_json, f, indent=2)
        
    # Write REPEATED_VALIDATION.md
    md_lines = [
        "# Repeated 5-Seed Cascade Domain-Disjoint Validation Report",
        "**Task ID**: `EXP-13-HIGH-RECALL-CASCADE-FP-REDUCTION-IMPLEMENTATION`  ",
        "**Date**: `2026-09-16`  ",
        "**Seeds Tested**: `[42, 101, 777, 2024, 9999]` (GroupShuffleSplit 80/20 grouped by apex domain)  ",
        "",
        "## 1. Aggregate Stability & Generalization Metrics",
        "",
        "| Candidate | Mean Phishing Recall | Recall Std | Worst-Seed Recall | Mean Overall FPR | Mean Sparse Legit FPR | Mean Precision | Total FNs (5 seeds) | Total FPs (5 seeds) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    ]
    for c in ["candidate_a", "candidate_b", "candidate_c", "candidate_d", "candidate_e"]:
        a = agg_summary[c]
        md_lines.append(
            f"| **{c.upper()}** | **{a['recall_mean']:.2f}%** | ±{a['recall_std']:.2f}% | "
            f"**{a['worst_seed_recall']:.2f}%** | {a['fpr_mean']:.2f}% | {a['sparse_fpr_mean']:.2f}% | "
            f"{a['precision_mean']:.2f}% | {a['total_fn']} | {a['total_fp']} |"
        )
        
    md_lines.extend([
        "",
        "## 2. Per-Seed Phishing Recall & FPR Breakdown",
        "",
        "| Seed | Candidate A (Base) | Candidate B (No Veto) | Candidate C (Borderline) | Candidate D (Strict Veto) | Candidate E (Cons. Cascade) |",
        "| :---: | :---: | :---: | :---: | :---: | :---: |"
    ])
    for s_idx, s in enumerate(seed_results):
        seed_val = s["seed"]
        row_str = f"| **Seed {seed_val}** | "
        items = []
        for c in ["candidate_a", "candidate_b", "candidate_c", "candidate_d", "candidate_e"]:
            rec = s[c]["recall"] * 100
            fpr = s[c]["fpr"] * 100
            items.append(f"Rec: {rec:.2f}%, FPR: {fpr:.2f}%")
        row_str += " | ".join(items) + " |"
        md_lines.append(row_str)
        
    with open(os.path.join(REPORTS_DIR, "REPEATED_VALIDATION.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines) + "\n")
        
    print(f"Repeated validation report written to {os.path.join(REPORTS_DIR, 'REPEATED_VALIDATION.md')}")
    return out_json

if __name__ == "__main__":
    run_repeated_validation()
