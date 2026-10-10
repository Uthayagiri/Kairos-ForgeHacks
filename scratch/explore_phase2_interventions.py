"""
Exploration of High-Value Single Interventions for Phase 2:
Intervention A: Free-PaaS / Cloud Subdomain Structural Signal (44 features)
Intervention B: Dual-End Contrastive Balanced Augmentation (adding legitimate auth AND high-link phish lures)
Intervention C: Link-Decoupled Form-Entropy Feature (cross-referencing form existence with domain depth)

Tests each candidate under exact production hyperparameters:
learning_rate=0.05, n_estimators=200, max_depth=4, colsample_bytree=0.7, subsample=0.95, reg_lambda=1.0, scale_pos_weight=5.0, random_state=42
"""

import sys
import os
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

with open(BACKEND_DIR / "ml" / "models" / "feature_columns.json", "r") as f:
    base_feature_cols = json.load(f)

dataset_path = BACKEND_DIR / "data" / "processed" / "training_dataset_expanded.csv"
raw_df = pd.read_csv(dataset_path)

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

if "registered_domain" not in raw_df.columns:
    raw_df["registered_domain"] = raw_df["url"].apply(extract_registered_domain)

gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
train_idx, test_idx = next(gss.split(raw_df, raw_df["label_binary"], groups=raw_df["registered_domain"]))

train_base = raw_df.iloc[train_idx].copy()
test_base = raw_df.iloc[test_idx].copy()

PROD_PARAMS = {
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

# --- Intervention A: Free PaaS / Dynamic Subdomain Hosting Signal ---
PAAS_DOMAINS = [
    "pages.dev", "netlify.app", "github.io", "webflow.io", "firebaseapp.com",
    "vercel.app", "render.com", "glitch.me", "surge.sh", "blogspot.com",
    "wordpress.com", "wixsite.com", "weebly.com", "000webhostapp.com",
    "sites.google.com", "s3.amazonaws.com", "blob.core.windows.net"
]

def extract_paas_subdomain_flag(url_str: str) -> int:
    try:
        host = urlparse(url_str if "://" in url_str else f"http://{url_str}").hostname or ""
        host = host.lower()
        if any(host.endswith(d) and host != d for d in PAAS_DOMAINS):
            return 1
        return 0
    except Exception:
        return 0

raw_df_a = raw_df.copy()
raw_df_a["is_free_hosting_subdomain"] = raw_df_a["url"].apply(extract_paas_subdomain_flag)
feat_cols_a = base_feature_cols + ["is_free_hosting_subdomain"]

X_train_a = raw_df_a.iloc[train_idx][feat_cols_a]
y_train_a = raw_df_a.iloc[train_idx]["label_binary"].astype(int)
X_test_a = raw_df_a.iloc[test_idx][feat_cols_a]
y_test_a = raw_df_a.iloc[test_idx]["label_binary"].astype(int)

model_a = xgb.XGBClassifier(**PROD_PARAMS)
model_a.fit(X_train_a, y_train_a)
rec_a = recall_score(y_test_a, model_a.predict(X_test_a))
acc_a = accuracy_score(y_test_a, model_a.predict(X_test_a))
prec_a = precision_score(y_test_a, model_a.predict(X_test_a))
tn_a, fp_a, fn_a, tp_a = confusion_matrix(y_test_a, model_a.predict(X_test_a)).ravel()

print(f"Intervention A (Free PaaS Subdomain Feature):")
print(f"  Recall: {rec_a*100:.2f}% ({tp_a}/{tp_a+fn_a}) | FN: {fn_a} | FP: {fp_a} | Acc: {acc_a*100:.2f}% | Prec: {prec_a*100:.2f}%")

# --- Intervention B: Dual-End Contrastive Balanced Augmentation ---
# Add 150 verified legitimate sparse auth pages AND 150 high-link cloned phishing pages
np.random.seed(42)
test_dom_set = set(test_base["registered_domain"])

aug_legit = []
prefixes = ["auth", "login", "sso", "portal", "identity", "accounts", "my"]
root_stems = ["cornell", "columbia", "princeton", "yale", "dartmouth", "brown", "upenn", "workday", "servicenow", "zendesk", "hubspot", "datadog", "stripe", "shopify", "sap", "adobe", "intuit"]
tlds = [".edu", ".ac.in", ".com", ".org", ".net"]

for i in range(150):
    stem = root_stems[i % len(root_stems)] + f"{i // len(root_stems) if i >= len(root_stems) else ''}"
    tld = tlds[i % len(tlds)]
    reg_dom = f"{stem}{tld}"
    if reg_dom in test_dom_set:
        reg_dom = f"aug-{reg_dom}"
    sub = prefixes[i % len(prefixes)]
    full_url = f"https://{sub}.{reg_dom}/login"
    
    n_links = int(np.random.choice([0, 1, 2, 3, 4, 5, 8, 10], p=[0.10, 0.12, 0.15, 0.15, 0.15, 0.13, 0.10, 0.10]))
    n_int = n_links if n_links <= 4 else n_links - 2
    n_ext = n_links - n_int
    ext_ratio = float(n_ext / n_links) if n_links > 0 else 0.0
    
    aug_legit.append({
        "url": full_url, "label_binary": 0, "label": "legitimate", "registered_domain": reg_dom,
        "url_length": len(full_url), "domain_length": len(f"{sub}.{reg_dom}"), "path_length": 6,
        "num_dots": full_url.count(".") - 1, "num_hyphens": full_url.count("-"), "num_underscores": 0,
        "num_slashes": full_url.count("/"), "num_digits": 0, "num_special_chars": 0,
        "num_subdomains": 1, "num_query_params": 0, "path_depth": 1,
        "has_at_symbol": 0, "has_ip_address": 0, "uses_https": 1, "has_port": 0,
        "has_url_encoding": 0, "has_suspicious_tld": 0, "has_suspicious_keywords": 1,
        "has_double_slash_redirect": 0, "is_shortened_url": 0, "url_parse_error": 0,
        "num_forms": 1, "num_input_fields": 3, "num_password_fields": 1,
        "has_login_form": 1, "num_forms_with_external_action": 0,
        "has_form_action_empty_or_javascript": 0,
        "num_links": n_links, "num_internal_links": n_int, "num_external_links": n_ext,
        "external_link_ratio": ext_ratio, "num_links_with_mismatched_text": 0,
        "num_scripts": np.random.randint(6, 20), "num_iframes": 0, "has_hidden_iframe": 0,
        "has_suspicious_js_patterns": 0, "num_meta_refresh_redirects": 0,
        "title_length": 25, "has_favicon": 1, "num_images": 3,
        "text_to_html_ratio": np.random.uniform(0.06, 0.18), "html_parse_error": 0
    })

# Add 150 high-link cloned phishing pages (e.g. brand lures on lookalikes/PaaS with 30-150 links)
aug_phish = []
phish_stems = ["verify-apple-security", "chase-online-recovery", "paypal-auth-session", "microsoft-sec-login", "netflix-billing-update"]
phish_tlds = [".top", ".xyz", ".club", ".info", ".cc", ".site"]

for i in range(150):
    stem = phish_stems[i % len(phish_stems)] + f"{i // len(phish_stems)}"
    tld = phish_tlds[i % len(phish_tlds)]
    reg_dom = f"{stem}{tld}"
    if reg_dom in test_dom_set:
        reg_dom = f"aug-{reg_dom}"
    full_url = f"http://{reg_dom}/signin/index.php"
    
    n_links = int(np.random.randint(30, 150))
    n_int = int(n_links * np.random.uniform(0.7, 0.95))
    n_ext = n_links - n_int
    ext_ratio = float(n_ext / n_links)
    
    aug_phish.append({
        "url": full_url, "label_binary": 1, "label": "phishing", "registered_domain": reg_dom,
        "url_length": len(full_url), "domain_length": len(reg_dom), "path_length": 17,
        "num_dots": full_url.count(".") - 1, "num_hyphens": full_url.count("-"), "num_underscores": 0,
        "num_slashes": full_url.count("/"), "num_digits": 0, "num_special_chars": 0,
        "num_subdomains": 0, "num_query_params": 0, "path_depth": 2,
        "has_at_symbol": 0, "has_ip_address": 0, "uses_https": 0 if i % 3 == 0 else 1, "has_port": 0,
        "has_url_encoding": 0, "has_suspicious_tld": 1 if tld in [".top", ".xyz", ".club"] else 0, "has_suspicious_keywords": 1,
        "has_double_slash_redirect": 0, "is_shortened_url": 0, "url_parse_error": 0,
        "num_forms": 1, "num_input_fields": 3, "num_password_fields": 1,
        "has_login_form": 1, "num_forms_with_external_action": 1 if i % 2 == 0 else 0,
        "has_form_action_empty_or_javascript": 0 if i % 2 == 0 else 1,
        "num_links": n_links, "num_internal_links": n_int, "num_external_links": n_ext,
        "external_link_ratio": ext_ratio, "num_links_with_mismatched_text": np.random.randint(0, 3),
        "num_scripts": np.random.randint(4, 15), "num_iframes": 0, "has_hidden_iframe": 0,
        "has_suspicious_js_patterns": 0, "num_meta_refresh_redirects": 0,
        "title_length": 22, "has_favicon": 1, "num_images": 5,
        "text_to_html_ratio": np.random.uniform(0.04, 0.12), "html_parse_error": 0
    })

train_b = pd.concat([train_base, pd.DataFrame(aug_legit), pd.DataFrame(aug_phish)], ignore_index=True)
X_train_b = train_b[base_feature_cols]
y_train_b = train_b["label_binary"].astype(int)
X_test_b = test_base[base_feature_cols]
y_test_b = test_base["label_binary"].astype(int)

model_b = xgb.XGBClassifier(**PROD_PARAMS)
model_b.fit(X_train_b, y_train_b)
rec_b = recall_score(y_test_b, model_b.predict(X_test_b))
acc_b = accuracy_score(y_test_b, model_b.predict(X_test_b))
prec_b = precision_score(y_test_b, model_b.predict(X_test_b))
tn_b, fp_b, fn_b, tp_b = confusion_matrix(y_test_b, model_b.predict(X_test_b)).ravel()

print(f"\nIntervention B (Dual-End Contrastive Balanced Augmentation):")
print(f"  Recall: {rec_b*100:.2f}% ({tp_b}/{tp_b+fn_b}) | FN: {fn_b} | FP: {fp_b} | Acc: {acc_b*100:.2f}% | Prec: {prec_b*100:.2f}%")
