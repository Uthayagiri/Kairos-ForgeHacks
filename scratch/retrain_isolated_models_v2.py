"""
Dedicated Retraining & Evaluation Script for Isolated Candidates V2
Explicitly trains:
  - candidate_m1_isolated_inst_v2.joblib
  - candidate_m2_isolated_aug_v2.joblib

Parameters explicitly passed:
  learning_rate = 0.05
  n_estimators = 200
  max_depth = 4
  colsample_bytree = 0.7
  subsample = 0.95
  reg_lambda = 1.0
  scale_pos_weight = 5.0
  eval_metric = "logloss"
  random_state = 42
  n_jobs = -1
"""

import sys
import os
import time
import json
import hashlib
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from urllib.parse import urlparse
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, brier_score_loss, roc_auc_score
)
import xgboost as xgb

REPO_ROOT = Path("c:/Users/Udhaya/S5_Phishing_Detector").resolve()
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.detection_engine import DetectionEngine
from app.services.risk_scoring import map_status_and_risk
from ml.feature_extraction import extract_url_features, extract_html_features, is_likely_unrendered_spa_shell
from ml.feature_extraction.html_features import get_default_html_feature_dict

print("=" * 80)
print("RETRAINING EXPERIMENTAL CANDIDATES V2 WITH EXPLICIT PRODUCTION HYPERPARAMETERS")
print("=" * 80)

# 1. Load Data
dataset_path = BACKEND_DIR / "data" / "processed" / "training_dataset_expanded.csv"
raw_data = pd.read_csv(dataset_path)

with open(BACKEND_DIR / "ml" / "models" / "feature_columns.json", "r") as f:
    base_feature_cols = json.load(f)

def extract_registered_domain(url_str: str) -> str:
    try:
        if not isinstance(url_str, str) or not url_str.strip():
            return "unknown"
        target = url_str if "://" in url_str else f"http://{url_str}"
        host = urlparse(target).hostname or "unknown"
        host = host.lower().strip(".")
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return "unknown"

if "registered_domain" not in raw_data.columns:
    raw_data["registered_domain"] = raw_data["url"].apply(extract_registered_domain)

gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
train_idx, test_idx = next(gss.split(raw_data, raw_data["label_binary"], groups=raw_data["registered_domain"]))

train_base = raw_data.iloc[train_idx].copy()
test_base = raw_data.iloc[test_idx].copy()

# Production Model (Control)
prod_path = BACKEND_DIR / "ml" / "models" / "phishing_model.joblib"
model_prod = joblib.load(prod_path)

# 2. Define Exact Explicit Hyperparameters
EXACT_PROD_PARAMS = {
    "max_depth": 4,
    "learning_rate": 0.05,
    "n_estimators": 200,
    "colsample_bytree": 0.7,
    "subsample": 0.95,
    "reg_lambda": 1.0,
    "scale_pos_weight": 5.0,
    "eval_metric": "logloss",
    "random_state": 42,
    "n_jobs": -1
}

print(f"\nLiteral Hyperparameter Arguments Passed to XGBoost:")
for k, v in EXACT_PROD_PARAMS.items():
    print(f"  {k}: {v}")

CANDIDATES_DIR = BACKEND_DIR / "ml" / "models" / "candidates_auth"
CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)

# 3. Retrain Experimental Model 1 V2 (+is_institutional_domain)
def get_institutional_flag(url_str: str) -> int:
    try:
        host = urlparse(url_str if "://" in url_str else f"http://{url_str}").hostname or ""
        host = host.lower()
        institutional_tlds = [
            ".edu", ".ac.in", ".gov", ".gov.in", ".edu.au", ".ac.uk",
            ".edu.cn", ".edu.sg", ".res.in", ".mil", ".edu.in", ".gov.uk"
        ]
        if any(host.endswith(tld) or f"{tld}." in host for tld in institutional_tlds):
            return 1
        return 0
    except Exception:
        return 0

raw_data_m1 = raw_data.copy()
raw_data_m1["is_institutional_domain"] = raw_data_m1["url"].apply(get_institutional_flag)
feature_cols_m1 = base_feature_cols + ["is_institutional_domain"]

train_m1 = raw_data_m1.iloc[train_idx].copy()
test_m1 = raw_data_m1.iloc[test_idx].copy()

X_train_m1 = train_m1[feature_cols_m1]
y_train_m1 = train_m1["label_binary"].astype(int)
X_test_m1 = test_m1[feature_cols_m1]
y_test_m1 = test_m1["label_binary"].astype(int)

print("\nFitting Experimental Model 1 V2...")
model_m1_v2 = xgb.XGBClassifier(**EXACT_PROD_PARAMS)
model_m1_v2.fit(X_train_m1, y_train_m1)
m1_v2_path = CANDIDATES_DIR / "candidate_m1_isolated_inst_v2.joblib"
joblib.dump(model_m1_v2, m1_v2_path)

# 4. Retrain Experimental Model 2 V2 (Targeted Sparse/Auth Data Augmentation)
np.random.seed(42)
num_aug = 300
aug_rows = []
test_dom_set = set(test_base["registered_domain"])
prefixes = ["auth", "login", "sso", "portal", "identity", "accounts", "connect", "secure", "idp", "my"]
root_stems = [
    "cornell", "columbia", "princeton", "yale", "dartmouth", "brown", "upenn",
    "caltech", "uchicago", "jhu", "northwestern", "duke", "vanderbilt", "rice",
    "notredame", "georgetown", "emory", "cmu", "virginia", "tufts",
    "workday", "servicenow", "zendesk", "hubspot", "datadog", "stripe", "shopify",
    "github", "gitlab", "bitbucket", "docker", "digitalocean", "cloudflare",
    "sap", "adobe", "intuit", "autodesk", "vmware", "splunk", "atlassian",
    "accenture", "deloitte", "kpmg", "pwc", "mckinsey", "bain", "bcg",
    "fidelity", "vanguard", "schwab", "blackrock", "state_street", "prudential"
]
tlds = [".edu", ".ac.in", ".ac.uk", ".edu.au", ".com", ".org", ".net", ".io"]

for i in range(num_aug):
    stem = root_stems[i % len(root_stems)] + f"{i // len(root_stems) if i >= len(root_stems) else ''}"
    tld = tlds[i % len(tlds)]
    reg_dom = f"{stem}{tld}"
    if reg_dom in test_dom_set:
        reg_dom = f"aug-{reg_dom}"
    sub = prefixes[i % len(prefixes)]
    full_url = f"https://{sub}.{reg_dom}/login"
    dom_len = len(f"{sub}.{reg_dom}")
    path_len = 5 + np.random.randint(0, 10)
    url_len = len(full_url)
    num_sub = 1 if sub else 0
    n_links = int(np.random.choice([0, 1, 2, 3, 4, 5, 8, 10, 12, 15, 18], p=[0.08, 0.10, 0.12, 0.12, 0.12, 0.12, 0.12, 0.08, 0.06, 0.04, 0.04]))
    if n_links == 0:
        n_int = 0; n_ext = 0; ext_ratio = 0.0
    else:
        n_ext = int(np.random.choice(range(min(n_links + 1, 4))))
        n_int = n_links - n_ext
        ext_ratio = float(n_ext / n_links)
    has_form = 1 if n_links > 0 or np.random.rand() > 0.3 else 0
    n_forms = 1 if has_form else (1 if np.random.rand() > 0.5 else 0)
    n_pass = 1 if has_form else 0
    n_inputs = (2 + np.random.randint(0, 3)) if has_form else np.random.randint(0, 2)
    n_scripts = np.random.randint(2, 30)
    
    aug_rows.append({
        "url": full_url, "label_binary": 0, "label": "legitimate", "registered_domain": reg_dom,
        "url_length": url_len, "domain_length": dom_len, "path_length": path_len,
        "num_dots": full_url.count(".") - 1, "num_hyphens": full_url.count("-"), "num_underscores": 0,
        "num_slashes": full_url.count("/"), "num_digits": 0, "num_special_chars": 0,
        "num_subdomains": num_sub, "num_query_params": 0, "path_depth": 1,
        "has_at_symbol": 0, "has_ip_address": 0, "uses_https": 1, "has_port": 0,
        "has_url_encoding": 0, "has_suspicious_tld": 0, "has_suspicious_keywords": 1 if "login" in full_url else 0,
        "has_double_slash_redirect": 0, "is_shortened_url": 0, "url_parse_error": 0,
        "num_forms": n_forms, "num_input_fields": n_inputs, "num_password_fields": n_pass,
        "has_login_form": has_form, "num_forms_with_external_action": 0,
        "has_form_action_empty_or_javascript": 0 if np.random.rand() > 0.2 else 1,
        "num_links": n_links, "num_internal_links": n_int, "num_external_links": n_ext,
        "external_link_ratio": ext_ratio, "num_links_with_mismatched_text": 0,
        "num_scripts": n_scripts, "num_iframes": 0, "has_hidden_iframe": 0,
        "has_suspicious_js_patterns": 0, "num_meta_refresh_redirects": 0,
        "title_length": np.random.randint(15, 50), "has_favicon": 1, "num_images": np.random.randint(1, 8),
        "text_to_html_ratio": np.random.uniform(0.02, 0.15), "html_parse_error": 0
    })

aug_df = pd.DataFrame(aug_rows)
train_m2 = pd.concat([train_base, aug_df], ignore_index=True)
X_train_m2 = train_m2[base_feature_cols]
y_train_m2 = train_m2["label_binary"].astype(int)

print("\nFitting Experimental Model 2 V2...")
model_m2_v2 = xgb.XGBClassifier(**EXACT_PROD_PARAMS)
model_m2_v2.fit(X_train_m2, y_train_m2)
m2_v2_path = CANDIDATES_DIR / "candidate_m2_isolated_aug_v2.joblib"
joblib.dump(model_m2_v2, m2_v2_path)

def get_hash(p: Path) -> str:
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

models_dict_v2 = {
    "Current Production (Control)": {
        "path": str(prod_path),
        "sha256": get_hash(prod_path),
        "model": model_prod,
        "cols": base_feature_cols,
        "has_inst": False,
        "desc": "Baseline (43 features, 7,111 training samples)"
    },
    "Experimental Model 1 V2": {
        "path": str(m1_v2_path),
        "sha256": get_hash(m1_v2_path),
        "model": model_m1_v2,
        "cols": feature_cols_m1,
        "has_inst": True,
        "desc": "+is_institutional_domain (44 features, 7,111 training samples)"
    },
    "Experimental Model 2 V2": {
        "path": str(m2_v2_path),
        "sha256": get_hash(m2_v2_path),
        "model": model_m2_v2,
        "cols": base_feature_cols,
        "has_inst": False,
        "desc": "Targeted Sparse/Auth Augmentation (43 features, 7,411 training samples)"
    }
}

print("\n" + "=" * 80)
print("NEWLY GENERATED MODEL ARTIFACT HASHEs & PROVENANCE")
print("=" * 80)
for k, v in models_dict_v2.items():
    print(f"{k}:")
    print(f"  Path:   {v['path']}")
    print(f"  SHA256: {v['sha256']}")
    print(f"  MTime:  {time.ctime(os.path.getmtime(v['path']))}")

# 5. Held-Out Domain-Split Test Evaluation
test_rows_v2 = []
for k, v in models_dict_v2.items():
    m = v["model"]
    cols = v["cols"]
    df_eval = test_m1 if v["has_inst"] else test_base
    X_t = df_eval[cols]
    y_t = df_eval["label_binary"].astype(int)
    
    y_p = m.predict(X_t)
    y_prob = m.predict_proba(X_t)[:, 1]
    
    acc = accuracy_score(y_t, y_p)
    prec = precision_score(y_t, y_p, zero_division=0)
    rec = recall_score(y_t, y_p, zero_division=0)
    f1 = f1_score(y_t, y_p, zero_division=0)
    brier = brier_score_loss(y_t, y_prob)
    roc_auc = roc_auc_score(y_t, y_prob)
    cm = confusion_matrix(y_t, y_p)
    tn, fp, fn, tp = cm.ravel()
    
    booster = m.get_booster()
    scores = booster.get_score(importance_type="gain")
    total_g = sum(scores.values())
    sorted_f = sorted([(feat, score/total_g) for feat, score in scores.items()], key=lambda x: x[1], reverse=True)
    top2_c = sum([val for _, val in sorted_f[:2]])
    
    test_rows_v2.append({
        "Model": k,
        "SHA-256 (First 12)": v["sha256"][:12],
        "Accuracy": f"{acc*100:.2f}%",
        "Precision": f"{prec*100:.2f}%",
        "Recall": f"{rec*100:.2f}%",
        "Recall Floor (>=94%)": "PASS" if rec >= 0.940 else f"FAIL ({rec*100:.2f}%)",
        "FN Missed": fn,
        "FP Alarms": fp,
        "F1-Score": f"{f1*100:.2f}%",
        "ROC-AUC": f"{roc_auc:.4f}",
        "Brier": f"{brier:.4f}",
        "Top-2 Conc": f"{top2_c*100:.2f}%"
    })

print("\n" + "=" * 80)
print("HELD-OUT TEST SET PERFORMANCE (1,799 SAMPLES, 0.00% DOMAIN LEAKAGE)")
print("=" * 80)
print(pd.DataFrame(test_rows_v2).to_string(index=False))

# 6. 34-Site Real-World Benchmark Sweep
bench_categories = [
    ("https://ps.bitsathy.ac.in", "Bannari Amman College Portal", "Diagnostic / SPA"),
    ("https://accounts.google.com", "Google Accounts Login", "Diagnostic / Auth"),
    ("https://login.salesforce.com", "Salesforce Customer Portal", "Diagnostic / Auth"),
    ("https://tinyurl.com/app", "TinyURL Web App", "Diagnostic / Shortener"),
    ("https://login.microsoftonline.com", "Microsoft Online Entra ID", "Diagnostic / SPA Auth"),
    ("https://id.atlassian.com/login", "Atlassian Cloud ID SSO", "Diagnostic / SPA Auth"),
    
    ("https://canvas.harvard.edu", "Harvard University Canvas Portal", "Institutional / University"),
    ("https://login.stanford.edu", "Stanford University WebLogin SSO", "Institutional / University"),
    ("https://auth.berkeley.edu", "UC Berkeley CalNet Authentication", "Institutional / University"),
    ("https://sso.iitm.ac.in", "IIT Madras SSO Portal", "Institutional / University"),
    ("https://portal.mit.edu", "MIT WebSIS Student Portal", "Institutional / University"),
    ("https://sso.ox.ac.uk", "University of Oxford SSO Portal", "Institutional / University"),
    ("https://my.ucla.edu", "UCLA Student Portal", "Institutional / University"),
    
    ("https://auth0.com", "Auth0 Platform Portal", "Enterprise Identity / SSO"),
    ("https://signin.aws.amazon.com", "AWS Management Console", "Enterprise Identity / SSO"),
    ("https://github.com/login", "GitHub Developer Login", "Enterprise Identity / SSO"),
    ("https://gitlab.com/users/sign_in", "GitLab DevSecOps Signin", "Enterprise Identity / SSO"),
    ("https://login.okta.com", "Okta Identity Cloud SSO", "Enterprise Identity / SSO"),
    ("https://auth.pingidentity.com", "Ping Identity Enterprise SSO", "Enterprise Identity / SSO"),
    ("https://duo.com", "Cisco Duo Security MFA", "Enterprise Identity / SSO"),
    ("https://app.slack.com/sign-in", "Slack Enterprise Sign-In", "Enterprise Identity / SSO"),
    ("https://login.oracle.com", "Oracle Single Sign-On Cloud", "Enterprise Identity / SSO"),
    ("https://www.dropbox.com/login", "Dropbox Cloud Storage Login", "Enterprise Identity / SSO"),
    ("https://en.wikipedia.org/wiki/Phishing", "Wikipedia Educational Article", "Standard Non-Auth Control"),
    
    ("http://192.168.1.100/paypal/login.php", "Raw IP PayPal Phishing", "Phishing Attack"),
    ("http://paypal-account-security-update.xyz/login", "Suspicious TLD Brand Phish", "Phishing Attack"),
    ("http://appleid.verify-security-checkpoint.top", "Brand Spoof Apple ID", "Phishing Attack"),
    ("http://login.microsoftonline.com.secure-auth.club", "DGA / Brand Spoofing MS", "Phishing Attack"),
    ("http://irs-tax-refund-gov.site/refund.php", "Tax Refund Credential Lure", "Phishing Attack"),
    ("http://secure-banking-login.com.account-update.info/sign-in", "Subdomain Banking Phish", "Phishing Attack"),
    ("http://10.0.0.1/netflix/billing.php", "Raw IP Netflix Lure", "Phishing Attack"),
    ("http://instagram-security-badges.fun/verify.html", "Social Media Lure", "Phishing Attack"),
    ("http://metamask-wallet-recover.top/phrase.php", "Crypto Seed Harvesting", "Phishing Attack"),
    ("http://chase-bank-alert.online/authenticate", "Banking Phishing Lure", "Phishing Attack")
]

engine = DetectionEngine(fetch_timeout=5.0)

def build_features(url_features, html_features, add_inst=False, url_str=""):
    combined = {}
    for k, v in url_features.items():
        col = "url_parse_error" if k == "parse_error" else k
        combined[col] = int(v) if isinstance(v, bool) else v
    for k, v in html_features.items():
        col = "html_parse_error" if k == "parse_error" else k
        combined[col] = int(v) if isinstance(v, bool) else v
    if add_inst:
        combined["is_institutional_domain"] = get_institutional_flag(url_str)
    return combined

bench_results_v2 = []
for u, desc, cat in bench_categories:
    is_phish_url = "Phishing" in cat
    ok, html_c, err, ssl_e = (False, None, "Mocked", None) if is_phish_url else engine.fetch_single_html(u)
    hf = extract_html_features(html_c, u) if ok and html_c else get_default_html_feature_dict(parse_error=True)
    uf = extract_url_features(u)
    spa_flag = is_likely_unrendered_spa_shell(hf) if ok else False
    
    row = {"Target & Category": f"{desc} [{cat}]"}
    for model_name, info in models_dict_v2.items():
        m = info["model"]
        cols = info["cols"]
        f_d = build_features(uf, hf, add_inst=info["has_inst"], url_str=u)
        df_r = pd.DataFrame([f_d])[cols]
        raw_val = float(m.predict_proba(df_r)[0][1])
        _, risk_val, final_val = map_status_and_risk(raw_val, bool(m.predict(df_r)[0]), ok, uf, spa_flag)
        row[f"{model_name} Raw"] = f"{raw_val*100:.2f}%"
        row[f"{model_name} Final"] = f"{final_val*100:.2f}% ({risk_val})"
    bench_results_v2.append(row)

print("\n" + "=" * 80)
print("REAL-WORLD BENCHMARK THREE-WAY COMPARISON (V2 ARTIFACTS)")
print("=" * 80)
bench_df_v2 = pd.DataFrame(bench_results_v2)
print(bench_df_v2.to_string(index=False))

# 7. Latency Benchmark
print("\n" + "=" * 80)
print("INFERENCE LATENCY BENCHMARK (500 Runs per Model)")
print("=" * 80)

lat_rows_v2 = []
for model_name, info in models_dict_v2.items():
    m = info["model"]
    cols = info["cols"]
    dummy_f = build_features(uf, hf, add_inst=info["has_inst"], url_str="https://example.com")
    dummy_df = pd.DataFrame([dummy_f])[cols]
    
    times = []
    for _ in range(500):
        t0 = time.perf_counter()
        _ = m.predict_proba(dummy_df)
        times.append((time.perf_counter() - t0) * 1000.0)
    lat_rows_v2.append({
        "Model": model_name,
        "Mean": f"{np.mean(times):.3f} ms",
        "Median (P50)": f"{np.percentile(times, 50):.3f} ms",
        "P95": f"{np.percentile(times, 95):.3f} ms",
        "P99": f"{np.percentile(times, 99):.3f} ms"
    })

print(pd.DataFrame(lat_rows_v2).to_string(index=False))

# 8. Determinism Verification
print("\n" + "=" * 80)
print("DETERMINISM VERIFICATION (5 Runs Each on Diagnostic Targets)")
print("=" * 80)

diag_targets = [
    ("https://ps.bitsathy.ac.in", "College Portal"),
    ("https://accounts.google.com", "Google Accounts Login"),
    ("https://login.salesforce.com", "Salesforce Customer Login"),
    ("https://tinyurl.com/app", "TinyURL App")
]

for test_u, test_desc in diag_targets:
    ok, html_c, _, _ = engine.fetch_single_html(test_u)
    hf = extract_html_features(html_c, test_u) if ok and html_c else get_default_html_feature_dict(parse_error=True)
    uf = extract_url_features(test_u)
    spa_flag = is_likely_unrendered_spa_shell(hf) if ok else False
    
    print(f"\nTarget: {test_desc} ({test_u})")
    for model_name, info in models_dict_v2.items():
        m = info["model"]
        cols = info["cols"]
        f_d = build_features(uf, hf, add_inst=info["has_inst"], url_str=test_u)
        df_r = pd.DataFrame([f_d])[cols]
        run_scores = []
        for _ in range(5):
            raw = float(m.predict_proba(df_r)[0][1])
            _, _, final = map_status_and_risk(raw, bool(m.predict(df_r)[0]), ok, uf, spa_flag)
            run_scores.append(round(final, 4))
        is_det = len(set(run_scores)) == 1
        print(f"  {model_name:32s}: Scores = {[f'{s*100:.2f}%' for s in run_scores]} | Deterministic: {is_det}")

print("\n" + "=" * 80)
print("V2 EXPERIMENTAL EVALUATION COMPLETE")
print("=" * 80)
