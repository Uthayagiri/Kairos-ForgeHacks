"""Phase 1 Root Cause Diagnosis Script for PhishGuard AI.

Rigorously investigates:
1. Domain overlap leakage in the original Stage 5-7 train/test split.
2. Existing model performance on leaky test split vs. clean domain-grouped split.
3. Single-feature over-reliance on link counts and model sensitivity.
4. Legitimate vs Phishing feature distributions (link counts, forms, scripts).
5. Probability calibration (Brier score, reliability curve data).
6. Data diversity, domain concentration, and duplicate feature vectors.
"""

import json
import re
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import calibration_curve
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

# Paths
BACKEND_DIR = Path("backend")
DATASET_PATH = BACKEND_DIR / "data" / "processed" / "training_dataset.csv"
MODEL_PATH = BACKEND_DIR / "ml" / "models" / "phishing_model.joblib"
FEATURE_COLS_PATH = BACKEND_DIR / "ml" / "models" / "feature_columns.json"

def extract_registered_domain(url: str) -> str:
    """Extract registered domain (approximate 2-level or 3-level domain)."""
    try:
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower().strip()
        if ":" in host:
            host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        
        # Split by dots
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        
        # Handle common ccTLD patterns like .co.uk, .com.au, .ac.in, .gov.in
        two_part_tlds = {"co.uk", "ac.uk", "gov.uk", "ac.in", "gov.in", "co.in", "edu.in", "com.au", "net.au", "co.jp", "com.br", "co.za"}
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in two_part_tlds and len(parts) >= 3:
            return f"{parts[-3]}.{last_two}"
        
        return f"{parts[-2]}.{parts[-1]}"
    except Exception:
        return url


def run_diagnosis():
    print("=" * 80)
    print("PHASE 1: RIGOROUS ROOT-CAUSE DIAGNOSIS")
    print("=" * 80)

    # Load dataset
    df = pd.read_csv(DATASET_PATH)
    total_rows = len(df)
    print(f"Total dataset samples: {total_rows}")
    print(f"Class counts:\n{df['label'].value_counts()}\n")

    # Extract domains
    df["registered_domain"] = df["url"].apply(extract_registered_domain)
    unique_domains = df["registered_domain"].nunique()
    print(f"Total unique registered domains across dataset: {unique_domains}")

    # Domain frequency
    domain_counts = df["registered_domain"].value_counts()
    print(f"\nTop 15 most frequent domains in dataset:")
    for dom, count in domain_counts.head(15).items():
        dom_label = df[df['registered_domain'] == dom]['label'].iloc[0]
        print(f"  - {dom:35s}: {count:4d} rows ({dom_label})")

    # -------------------------------------------------------------
    # 1. DOMAIN OVERLAP LEAKAGE ANALYSIS
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("1. DOMAIN OVERLAP LEAKAGE ANALYSIS (Original Random Stratified Split)")
    print("-" * 80)

    # Replicate original 80/20 train/test split
    train_df, test_df = train_test_split(
        df,
        test_size=0.2,
        random_state=42,
        stratify=df["label_binary"],
    )

    train_domains = set(train_df["registered_domain"])
    test_domains = set(test_df["registered_domain"])
    overlap_domains = test_domains.intersection(train_domains)

    overlap_pct_domains = (len(overlap_domains) / len(test_domains)) * 100
    
    # Rows in test set belonging to overlapping domains
    leaky_test_rows = test_df[test_df["registered_domain"].isin(overlap_domains)]
    clean_test_rows = test_df[~test_df["registered_domain"].isin(overlap_domains)]
    
    leaky_row_pct = (len(leaky_test_rows) / len(test_df)) * 100

    print(f"Train split: {len(train_df)} rows, {len(train_domains)} unique domains")
    print(f"Test split:  {len(test_df)} rows, {len(test_domains)} unique domains")
    print(f"Overlapping domains in test set: {len(overlap_domains)} / {len(test_domains)} ({overlap_pct_domains:.2f}%)")
    print(f"Test rows with domains in train set: {len(leaky_test_rows)} / {len(test_df)} ({leaky_row_pct:.2f}%)")

    # Overlap by class
    legit_test = test_df[test_df["label_binary"] == 0]
    legit_train_domains = set(train_df[train_df["label_binary"] == 0]["registered_domain"])
    legit_overlap = set(legit_test["registered_domain"]).intersection(legit_train_domains)
    legit_leaky_rows = legit_test[legit_test["registered_domain"].isin(legit_train_domains)]

    phish_test = test_df[test_df["label_binary"] == 1]
    phish_train_domains = set(train_df[train_df["label_binary"] == 1]["registered_domain"])
    phish_overlap = set(phish_test["registered_domain"]).intersection(phish_train_domains)
    phish_leaky_rows = phish_test[phish_test["registered_domain"].isin(phish_train_domains)]

    print(f"\nLegitimate class leakage:")
    print(f"  - Overlapping domains: {len(legit_overlap)} / {legit_test['registered_domain'].nunique()} ({len(legit_overlap)/legit_test['registered_domain'].nunique()*100:.2f}%)")
    print(f"  - Test rows from seen domains: {len(legit_leaky_rows)} / {len(legit_test)} ({len(legit_leaky_rows)/len(legit_test)*100:.2f}%)")

    print(f"\nPhishing class leakage:")
    print(f"  - Overlapping domains: {len(phish_overlap)} / {phish_test['registered_domain'].nunique()} ({len(phish_overlap)/phish_test['registered_domain'].nunique()*100:.2f}%)")
    print(f"  - Test rows from seen domains: {len(phish_leaky_rows)} / {len(phish_test)} ({len(phish_leaky_rows)/len(phish_test)*100:.2f}%)")

    # -------------------------------------------------------------
    # 2. MODEL EVALUATION ON LEAKY VS UNSEEN DOMAIN SETS
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("2. EXISTING MODEL EVALUATION: LEAKY TEST SET VS CLEAN UNSEEN DOMAINS")
    print("-" * 80)

    model = joblib.load(MODEL_PATH)
    feature_cols = json.load(open(FEATURE_COLS_PATH))

    # Evaluate on full original test set
    X_test_orig = test_df[feature_cols]
    y_test_orig = test_df["label_binary"]
    y_prob_orig = model.predict_proba(X_test_orig)[:, 1]
    y_pred_orig = (y_prob_orig >= 0.5).astype(int)

    print("Full Original Test Set Metrics (Reported in Stage 7/14):")
    print(f"  - Accuracy:  {accuracy_score(y_test_orig, y_pred_orig):.4f}")
    print(f"  - Precision: {precision_score(y_test_orig, y_pred_orig):.4f}")
    print(f"  - Recall:    {recall_score(y_test_orig, y_pred_orig):.4f}")
    print(f"  - F1-Score:  {f1_score(y_test_orig, y_pred_orig):.4f}")
    print(f"  - ROC-AUC:   {roc_auc_score(y_test_orig, y_prob_orig):.4f}")
    print(f"  - Brier Loss:{brier_score_loss(y_test_orig, y_prob_orig):.4f}")

    # Evaluate on Leaky subset of test set
    X_leaky = leaky_test_rows[feature_cols]
    y_leaky = leaky_test_rows["label_binary"]
    y_prob_leaky = model.predict_proba(X_leaky)[:, 1]
    y_pred_leaky = (y_prob_leaky >= 0.5).astype(int)

    print(f"\nLeaky Test Subset ({len(leaky_test_rows)} rows — domains seen during training):")
    print(f"  - Accuracy:  {accuracy_score(y_leaky, y_pred_leaky):.4f}")
    print(f"  - Precision: {precision_score(y_leaky, y_pred_leaky):.4f}")
    print(f"  - Recall:    {recall_score(y_leaky, y_pred_leaky):.4f}")
    print(f"  - F1-Score:  {f1_score(y_leaky, y_pred_leaky):.4f}")

    # Evaluate on Clean Unseen subset of test set
    if len(clean_test_rows) > 0:
        X_clean = clean_test_rows[feature_cols]
        y_clean = clean_test_rows["label_binary"]
        y_prob_clean = model.predict_proba(X_clean)[:, 1]
        y_pred_clean = (y_prob_clean >= 0.5).astype(int)

        print(f"\nClean Unseen Test Subset ({len(clean_test_rows)} rows — domains NEVER in training):")
        print(f"  - Accuracy:  {accuracy_score(y_clean, y_pred_clean):.4f}")
        print(f"  - Precision: {precision_score(y_clean, y_pred_clean):.4f}")
        print(f"  - Recall:    {recall_score(y_clean, y_pred_clean):.4f}")
        print(f"  - F1-Score:  {f1_score(y_clean, y_pred_clean):.4f}")
        print(f"  - ROC-AUC:   {roc_auc_score(y_clean, y_prob_clean):.4f}")
        cm_clean = confusion_matrix(y_clean, y_pred_clean)
        print(f"  - Confusion Matrix:\n{cm_clean}")

    # -------------------------------------------------------------
    # 3. PROPER DOMAIN-GROUPED SPLIT EVALUATION
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("3. EXISTING MODEL ON STRICT DOMAIN-GROUPED SPLIT (GroupShuffleSplit)")
    print("-" * 80)

    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(df, groups=df["registered_domain"]))

    g_train_df = df.iloc[train_idx]
    g_test_df = df.iloc[test_idx]

    g_train_doms = set(g_train_df["registered_domain"])
    g_test_doms = set(g_test_df["registered_domain"])
    g_overlap = g_test_doms.intersection(g_train_doms)

    print(f"Domain-Grouped Train: {len(g_train_df)} rows, {len(g_train_doms)} unique domains")
    print(f"Domain-Grouped Test:  {len(g_test_df)} rows, {len(g_test_doms)} unique domains")
    print(f"Overlap: {len(g_overlap)} domains (0.00% verified)")

    X_gtest = g_test_df[feature_cols]
    y_gtest = g_test_df["label_binary"]
    y_gprob = model.predict_proba(X_gtest)[:, 1]
    y_gpred = (y_gprob >= 0.5).astype(int)

    print(f"\nExisting Model Performance on True Domain-Grouped Test Set:")
    print(f"  - Accuracy:  {accuracy_score(y_gtest, y_gpred):.4f}")
    print(f"  - Precision: {precision_score(y_gtest, y_gpred):.4f}")
    print(f"  - Recall:    {recall_score(y_gtest, y_gpred):.4f}")
    print(f"  - F1-Score:  {f1_score(y_gtest, y_gpred):.4f}")
    print(f"  - ROC-AUC:   {roc_auc_score(y_gtest, y_gprob):.4f}")
    print(f"  - Brier Loss:{brier_score_loss(y_gtest, y_gprob):.4f}")
    cm_g = confusion_matrix(y_gtest, y_gpred)
    print(f"  - Confusion Matrix (TN, FP, FN, TP):\n    TN={cm_g[0,0]}, FP={cm_g[0,1]}, FN={cm_g[1,0]}, TP={cm_g[1,1]}")
    print(f"  - False Positive Rate on Unseen Legitimate Domains: {cm_g[0,1]/(cm_g[0,0]+cm_g[0,1])*100:.2f}%")

    # -------------------------------------------------------------
    # 4. SINGLE-FEATURE OVER-RELIANCE & LINK COUNT DISTRIBUTION
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("4. SINGLE-FEATURE OVER-RELIANCE & FEATURE DISTRIBUTIONS")
    print("-" * 80)

    importances = model.feature_importances_
    fi = sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)
    print("Top 10 Feature Importances in Deployed Model:")
    for i, (name, imp) in enumerate(fi[:10]):
        print(f"  {i+1:2d}. {name:32s}: {imp:.6f} ({imp*100:.2f}%)")

    top2_weight = fi[0][1] + fi[1][1]
    print(f"\nCombined decision weight of top 2 features ({fi[0][0]} + {fi[1][0]}): {top2_weight*100:.2f}%")

    # Analyze link distribution in training dataset
    legit_df = df[df["label_binary"] == 0]
    phish_df = df[df["label_binary"] == 1]

    print("\nLink Count (num_links) Quantile Distribution:")
    print("  Legitimate:", legit_df["num_links"].quantile([0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99]).to_dict())
    print("  Phishing:  ", phish_df["num_links"].quantile([0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99]).to_dict())

    low_link_legit_10 = (legit_df["num_links"] <= 10).sum()
    low_link_legit_5 = (legit_df["num_links"] <= 5).sum()
    low_link_legit_0 = (legit_df["num_links"] == 0).sum()

    print(f"\nLegitimate samples with sparse links:")
    print(f"  - num_links <= 10: {low_link_legit_10} / {len(legit_df)} ({low_link_legit_10/len(legit_df)*100:.2f}%)")
    print(f"  - num_links <= 5:  {low_link_legit_5} / {len(legit_df)} ({low_link_legit_5/len(legit_df)*100:.2f}%)")
    print(f"  - num_links == 0:  {low_link_legit_0} / {len(legit_df)} ({low_link_legit_0/len(legit_df)*100:.2f}%)")

    high_link_phish_10 = (phish_df["num_links"] > 10).sum()
    print(f"\nPhishing samples with rich links:")
    print(f"  - num_links > 10: {high_link_phish_10} / {len(phish_df)} ({high_link_phish_10/len(phish_df)*100:.2f}%)")
    print(f"  - num_links == 0: {(phish_df['num_links'] == 0).sum()} / {len(phish_df)} ({(phish_df['num_links'] == 0).sum()/len(phish_df)*100:.2f}%)")

    # -------------------------------------------------------------
    # 5. PROBABILITY CALIBRATION AUDIT
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("5. PROBABILITY CALIBRATION & RELIABILITY CURVE DATA")
    print("-" * 80)

    prob_true, prob_pred = calibration_curve(y_gtest, y_gprob, n_bins=5, strategy="uniform")
    print("Reliability Curve Bins (Domain-Grouped Test Set):")
    for pt, pp in zip(prob_true, prob_pred):
        print(f"  - Predicted Mean Prob: {pp:.4f}  -->  Empirical Positive Rate: {pt:.4f}")

    # Check predicted probability distribution on legitimate test samples
    legit_gtest_probs = y_gprob[y_gtest == 0]
    print(f"\nPredicted Probabilities on Legitimate Test Samples (Domain-Grouped):")
    print(f"  - Mean: {legit_gtest_probs.mean():.4f}")
    print(f"  - Median: {np.median(legit_gtest_probs):.4f}")
    print(f"  - 75th percentile: {np.percentile(legit_gtest_probs, 75):.4f}")
    print(f"  - 90th percentile: {np.percentile(legit_gtest_probs, 90):.4f}")
    print(f"  - 95th percentile: {np.percentile(legit_gtest_probs, 95):.4f}")
    print(f"  - Max: {legit_gtest_probs.max():.4f}")

    # -------------------------------------------------------------
    # 6. DUPLICATE FEATURE VECTORS & DOMAIN CONCENTRATION
    # -------------------------------------------------------------
    print("\n" + "-" * 80)
    print("6. DUPLICATE FEATURE VECTORS & DOMAIN CONCENTRATION")
    print("-" * 80)

    feat_df = df[feature_cols]
    dup_feats = feat_df.duplicated().sum()
    print(f"Identical feature vectors across different URLs: {dup_feats} / {total_rows} ({dup_feats/total_rows*100:.2f}%)")

    # Check if duplicate feature vectors have conflicting labels
    dup_groups = df.groupby(feature_cols)["label_binary"].nunique()
    conflicting = (dup_groups > 1).sum()
    print(f"Conflicting label rows (same exact 43 features, different labels): {conflicting}")

    print("\n" + "=" * 80)
    print("PHASE 1 DIAGNOSTIC COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    run_diagnosis()
