"""Phase 4: Rigorous Multi-Set Evaluation.

Compares:
1. Old Deployed Model (Stage 7) vs. New Calibrated Model (Stage 14) on the SAME Domain-Grouped Test Set.
2. Side-by-side evaluation on a 50-URL genuinely UNSEEN Real-World Benchmark.
3. Specific tracking of the reported college portal (https://ps.bitsathy.ac.in).
4. Inference latency measurement.
"""

import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

BACKEND_DIR = Path("backend")
if str(BACKEND_DIR.resolve()) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR.resolve()))

from ml.feature_extraction import extract_html_features, extract_url_features
from app.services.detection_engine import DetectionEngine

DATASET_PATH = BACKEND_DIR / "data" / "processed" / "training_dataset_expanded.csv"
FEATURE_COLS_PATH = BACKEND_DIR / "ml" / "models" / "feature_columns.json"

OLD_MODEL_PATH = BACKEND_DIR / "ml" / "models" / "phishing_model.joblib"
NEW_SIGMOID_PATH = Path("scratch") / "model_candidates" / "phishing_model_v2_sigmoid.joblib"
NEW_ISOTONIC_PATH = Path("scratch") / "model_candidates" / "phishing_model_v2_isotonic.joblib"
NEW_BASE_PATH = Path("scratch") / "model_candidates" / "phishing_model_v2_uncalibrated.joblib"

# 50 Unseen Real-World Benchmark URLs
UNSEEN_BENCHMARK_URLS = [
    # 1. Higher Education & College Portals (8 URLs)
    {"url": "https://ps.bitsathy.ac.in", "type": "Legitimate College Portal (Reported Case)", "is_phish": False},
    {"url": "https://www.iitb.ac.in/en/academics/academic-divisions", "type": "Higher Education (.ac.in)", "is_phish": False},
    {"url": "https://www.iisc.ac.in/admissions/", "type": "Research Institution (.ac.in)", "is_phish": False},
    {"url": "https://home.iitd.ac.in/curriculum.php", "type": "Higher Education (.ac.in)", "is_phish": False},
    {"url": "https://www.stanford.edu/academics/", "type": "Higher Education (.edu)", "is_phish": False},
    {"url": "https://www.cam.ac.uk/research", "type": "Higher Education (.ac.uk)", "is_phish": False},
    {"url": "https://www.nus.edu.sg/admissions", "type": "Higher Education (.edu.sg)", "is_phish": False},
    {"url": "https://www.ox.ac.uk/admissions", "type": "Higher Education (.ac.uk)", "is_phish": False},

    # 2. Government & Municipal Service Portals (8 URLs)
    {"url": "https://www.india.gov.in/my-government/schemes", "type": "Government Portal (.gov.in)", "is_phish": False},
    {"url": "https://uidai.gov.in/en/my-aadhaar/get-aadhaar.html", "type": "Identity Services (.gov.in)", "is_phish": False},
    {"url": "https://www.incometax.gov.in/iec/foportal/", "type": "Taxation Portal (.gov.in)", "is_phish": False},
    {"url": "https://www.passportindia.gov.in/AppOnlineProject/welcomeLink", "type": "Passport Services (.gov.in)", "is_phish": False},
    {"url": "https://www.usa.gov/benefits", "type": "Government Portal (.gov)", "is_phish": False},
    {"url": "https://www.gov.uk/browse/benefits", "type": "Government Portal (.gov.uk)", "is_phish": False},
    {"url": "https://www.weather.gov/forecastmaps", "type": "Public Agency (.gov)", "is_phish": False},
    {"url": "https://www.cdc.gov/flu/index.htm", "type": "Health Agency (.gov)", "is_phish": False},

    # 3. Minimalist Tools, SaaS & Utility Landing Pages (8 URLs)
    {"url": "https://pastebin.com/archive", "type": "Utility / Text Sharing", "is_phish": False},
    {"url": "https://excalidraw.com", "type": "Client SPA Tool", "is_phish": False},
    {"url": "https://jsonlint.com", "type": "Developer Tool", "is_phish": False},
    {"url": "https://regex101.com", "type": "Developer Tool (SPA)", "is_phish": False},
    {"url": "https://www.diffchecker.com", "type": "Diff Utility", "is_phish": False},
    {"url": "https://www.wolframalpha.com/examples", "type": "Computation Engine", "is_phish": False},
    {"url": "https://www.speedtest.net", "type": "Network Tool", "is_phish": False},
    {"url": "https://archive.org/web/", "type": "Web Archive", "is_phish": False},

    # 4. Developer Platforms, Documentation & SPAs (8 URLs)
    {"url": "https://docs.python.org/3/library/json.html", "type": "Documentation Subpage", "is_phish": False},
    {"url": "https://developer.mozilla.org/en-US/docs/Web/JavaScript", "type": "MDN Documentation", "is_phish": False},
    {"url": "https://react.dev/reference/react", "type": "React SPA Docs", "is_phish": False},
    {"url": "https://fastapi.tiangolo.com/tutorial/", "type": "FastAPI Docs", "is_phish": False},
    {"url": "https://tailwindcss.com/docs/utility-first", "type": "CSS Framework Docs", "is_phish": False},
    {"url": "https://gitlab.com/explore", "type": "Developer Platform (SPA)", "is_phish": False},
    {"url": "https://github.com/features", "type": "Developer Platform", "is_phish": False},
    {"url": "https://news.ycombinator.com/news", "type": "Tech News Aggregator", "is_phish": False},

    # 5. Major Commercial, Media & Non-Profit (8 URLs)
    {"url": "https://www.bbc.com/news", "type": "News Media", "is_phish": False},
    {"url": "https://www.nytimes.com/section/world", "type": "News Media", "is_phish": False},
    {"url": "https://www.amazon.com/gp/goldbox", "type": "E-Commerce", "is_phish": False},
    {"url": "https://www.wikipedia.org", "type": "Reference Portal", "is_phish": False},
    {"url": "https://www.redcross.org/get-help.html", "type": "Non-Profit Humanitarian", "is_phish": False},
    {"url": "https://www.unicef.org/press-releases", "type": "International NGO", "is_phish": False},
    {"url": "https://www.who.int/news", "type": "Global Health Agency", "is_phish": False},
    {"url": "https://dev.to/top/week", "type": "Community Blog", "is_phish": False},

    # 6. Synthetic / Constructed Phishing Attack Patterns (10 URLs)
    {"url": "http://192.168.1.100/paypal/login.php", "type": "Raw IP + Brand Keyword", "is_phish": True},
    {"url": "http://10.0.0.1/secure-banking/verification.html", "type": "Private IP + Banking Auth", "is_phish": True},
    {"url": "http://paypal-account-verification.security-update.xyz/login.php", "type": "Spoofed Subdomain + .xyz TLD", "is_phish": True},
    {"url": "http://wellsfargo.com.security-alert-service.top/auth/signin.html", "type": ".top TLD + Bank Spoof", "is_phish": True},
    {"url": "http://chase-bank-verify-identity.support-desk.account-update.tk/index.html", "type": "Excessive subdomains + .tk", "is_phish": True},
    {"url": "http://172.16.254.1:8080/apple/id/account/billing/signin", "type": "Non-standard port + Raw IP", "is_phish": True},
    {"url": "http://apple-id-verify-billing.account-security-check.icu/signin", "type": ".icu TLD + Brand Auth", "is_phish": True},
    {"url": "http://netflix-billing-update-center.membership-verify.live/login", "type": ".live TLD + Auth Keywords", "is_phish": True},
    {"url": "http://secure-login-chase-online.web-portal-auth.cf/verify.html", "type": ".cf TLD + Multi-Subdomain", "is_phish": True},
    {"url": "http://microsoft-365-security-checkpoint.login-office.site/auth.php", "type": ".site TLD + Office Spoof", "is_phish": True},
]


def extract_feature_vector_for_url(url: str, feature_cols: List[str], engine: DetectionEngine) -> pd.DataFrame:
    """Extract full 43-feature vector for a live URL."""
    url_feats = extract_url_features(url)
    success, html_content, _, _ = engine.fetch_single_html(url)
    html_feats = extract_html_features(html_content, page_url=url) if success and html_content else {}

    combined = {}
    for k, v in url_feats.items():
        col_name = "url_parse_error" if k == "parse_error" else k
        combined[col_name] = int(v) if isinstance(v, bool) else v
    for k, v in html_feats.items():
        col_name = "html_parse_error" if k == "parse_error" else k
        combined[col_name] = int(v) if isinstance(v, bool) else v

    return pd.DataFrame([[combined.get(c, 0) for c in feature_cols]], columns=feature_cols)


def run_evaluation():
    print("=" * 80)
    print("PHASE 4: RIGOROUS MULTI-SET EVALUATION & COMPARISON")
    print("=" * 80)

    # 1. Load models
    old_model = joblib.load(OLD_MODEL_PATH)
    new_sigmoid = joblib.load(NEW_SIGMOID_PATH)
    new_isotonic = joblib.load(NEW_ISOTONIC_PATH)
    new_base = joblib.load(NEW_BASE_PATH)
    feature_cols = json.load(open(FEATURE_COLS_PATH))

    # 2. Evaluate on the Domain-Grouped Test Set
    df = pd.read_csv(DATASET_PATH)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(df, groups=df["registered_domain"]))
    test_df = df.iloc[test_idx]

    X_test = test_df[feature_cols]
    y_test = test_df["label_binary"]

    print("\n" + "-" * 80)
    print("PART A: HELD-OUT DOMAIN-GROUPED TEST SET (Apples-to-Apples)")
    print("-" * 80)
    print(f"Test Set Size: {len(test_df)} samples ({test_df['registered_domain'].nunique()} unique domains)")
    print(f"Class counts: Legitimate = {(y_test==0).sum()}, Phishing = {(y_test==1).sum()}\n")

    models_to_test = [
        ("Old Deployed Model (Stage 7)", old_model),
        ("New Regularized Base XGBoost", new_base),
        ("New Calibrated XGBoost (Sigmoid)", new_sigmoid),
        ("New Calibrated XGBoost (Isotonic)", new_isotonic),
    ]

    print(f"{'Model Configuration':<35} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<8} | {'F1':<8} | {'ROC-AUC':<8} | {'Brier':<8}")
    print("-" * 95)

    for name, m in models_to_test:
        probs = m.predict_proba(X_test)[:, 1]
        preds = (probs >= 0.5).astype(int)
        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds)
        rec = recall_score(y_test, preds)
        f1 = f1_score(y_test, preds)
        auc = roc_auc_score(y_test, probs)
        brier = brier_score_loss(y_test, probs)
        print(f"{name:<35} | {acc:.4f}   | {prec:.4f}    | {rec:.4f}   | {f1:.4f}   | {auc:.4f}   | {brier:.4f}")

    # 3. Evaluate on 50 Unseen Real-World Benchmark URLs
    print("\n" + "-" * 80)
    print("PART B: 50 UNSEEN REAL-WORLD BENCHMARK EVALUATION (SIDE-BY-SIDE)")
    print("-" * 80)

    engine = DetectionEngine()
    results = []

    print(f"Executing live evaluation across {len(UNSEEN_BENCHMARK_URLS)} unseen URLs...\n")

    latencies_old = []
    latencies_new = []

    for item in UNSEEN_BENCHMARK_URLS:
        url = item["url"]
        is_phish_expected = item["is_phish"]
        u_type = item["type"]

        vec = extract_feature_vector_for_url(url, feature_cols, engine)

        # Old model timing
        t0 = time.perf_counter()
        prob_old = old_model.predict_proba(vec)[0, 1]
        lat_old = (time.perf_counter() - t0) * 1000.0
        latencies_old.append(lat_old)

        # New Calibrated model (Sigmoid) timing
        t1 = time.perf_counter()
        prob_new_sig = new_sigmoid.predict_proba(vec)[0, 1]
        lat_new = (time.perf_counter() - t1) * 1000.0
        latencies_new.append(lat_new)

        # New Calibrated model (Isotonic)
        prob_new_iso = new_isotonic.predict_proba(vec)[0, 1]

        pred_old = "PHISHING" if prob_old >= 0.5 else "SAFE"
        pred_new = "PHISHING" if prob_new_sig >= 0.5 else "SAFE"

        match_old = (prob_old >= 0.5) == is_phish_expected
        match_new = (prob_new_sig >= 0.5) == is_phish_expected

        results.append({
            "url": url,
            "type": u_type,
            "expected": "PHISHING" if is_phish_expected else "SAFE",
            "old_prob": float(prob_old),
            "old_verdict": pred_old,
            "old_match": bool(match_old),
            "new_prob": float(prob_new_sig),
            "new_verdict": pred_new,
            "new_match": bool(match_new),
            "iso_prob": float(prob_new_iso),
        })

    # Print Side-by-Side Table
    print(f"{'#':<3} | {'URL':<50} | {'Expected':<8} | {'Old Prob':<9} | {'Old Verd':<8} | {'New Prob':<9} | {'New Verd':<8}")
    print("-" * 110)
    for i, r in enumerate(results):
        u_short = r["url"] if len(r["url"]) <= 48 else r["url"][:45] + "..."
        print(f"{i+1:<3} | {u_short:<50} | {r['expected']:<8} | {r['old_prob']*100:6.2f}%   | {r['old_verdict']:<8} | {r['new_prob']*100:6.2f}%   | {r['new_verdict']:<8}")

    # Summary Statistics on Unseen Benchmark
    df_res = pd.DataFrame(results)
    old_correct = df_res["old_match"].sum()
    new_correct = df_res["new_match"].sum()

    old_fps = ((df_res["expected"] == "SAFE") & (df_res["old_verdict"] == "PHISHING")).sum()
    new_fps = ((df_res["expected"] == "SAFE") & (df_res["new_verdict"] == "PHISHING")).sum()

    old_fns = ((df_res["expected"] == "PHISHING") & (df_res["old_verdict"] == "SAFE")).sum()
    new_fns = ((df_res["expected"] == "PHISHING") & (df_res["new_verdict"] == "SAFE")).sum()

    print("\n" + "=" * 80)
    print("UNSEEN REAL-WORLD BENCHMARK SUMMARY (N = 50 URLs)")
    print("=" * 80)
    print(f"Overall Accuracy:  Old Model = {old_correct}/{len(results)} ({old_correct/len(results)*100:.1f}%)  |  New Calibrated = {new_correct}/{len(results)} ({new_correct/len(results)*100:.1f}%)")
    print(f"False Positives:   Old Model = {old_fps} / 40 legitimate  |  New Calibrated = {new_fps} / 40 legitimate")
    print(f"False Negatives:   Old Model = {old_fns} / 10 attacks     |  New Calibrated = {new_fns} / 10 attacks")
    print(f"Mean Inference Latency: Old = {np.mean(latencies_old):.3f} ms  |  New = {np.mean(latencies_new):.3f} ms")

    # Specific check on problem case
    bitsathy_row = [r for r in results if "bitsathy" in r["url"]][0]
    print(f"\n--- REPORTED PROBLEM CASE (https://ps.bitsathy.ac.in) ---")
    print(f"  Old Model Raw Phishing Probability: {bitsathy_row['old_prob']*100:.2f}%  (Verdict: {bitsathy_row['old_verdict']})")
    print(f"  New Model (Sigmoid) Probability:    {bitsathy_row['new_prob']*100:.2f}%  (Verdict: {bitsathy_row['new_verdict']})")
    print(f"  New Model (Isotonic) Probability:   {bitsathy_row['iso_prob']*100:.2f}%")
    print("=" * 80)

    # Save results to JSON
    with open("scratch/phase4_evaluation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("Full results written to scratch/phase4_evaluation_results.json")


if __name__ == "__main__":
    run_evaluation()
