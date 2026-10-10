"""
Generalization Check on Unlisted Free-Hosting / PaaS Platforms
Tests whether Candidate Exp 3 (is_free_hosting_subdomain) generalizes to
unlisted free hosting / PaaS platforms:
- replit.app
- fly.dev
- railway.app
- workers.dev
- deno.dev
- cyclic.app
- supabase.co

Evaluates both Control and Candidate Exp 3 on high-link cloned attacks on these platforms.
"""

import sys
import os
import json
import hashlib
import joblib
import pandas as pd
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path("c:/Users/Udhaya/S5_Phishing_Detector").resolve()
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from ml.feature_extraction import extract_url_features
from ml.feature_extraction.html_features import get_default_html_feature_dict

with open(BACKEND_DIR / "ml" / "models" / "feature_columns.json", "r") as f:
    base_feature_cols = json.load(f)

feat_cols_exp3 = base_feature_cols + ["is_free_hosting_subdomain"]

prod_path = BACKEND_DIR / "ml" / "models" / "phishing_model.joblib"
exp3_path = BACKEND_DIR / "ml" / "models" / "candidates_auth" / "candidate_exp3_paas_signal.joblib"

model_prod = joblib.load(prod_path)
model_exp3 = joblib.load(exp3_path)

with open(prod_path, "rb") as f:
    prod_sha = hashlib.sha256(f.read()).hexdigest()
with open(exp3_path, "rb") as f:
    exp3_sha = hashlib.sha256(f.read()).hexdigest()

PAAS_LIST_EXP3 = [
    "pages.dev", "netlify.app", "github.io", "webflow.io", "firebaseapp.com",
    "vercel.app", "render.com", "glitch.me", "surge.sh", "blogspot.com",
    "wordpress.com", "wixsite.com", "weebly.com", "000webhostapp.com",
    "sites.google.com", "s3.amazonaws.com", "blob.core.windows.net", "dub.sh"
]

def get_paas_flag(url_str: str) -> int:
    try:
        host = urlparse(url_str if "://" in url_str else f"http://{url_str}").hostname or ""
        host = host.lower()
        if any(host.endswith(d) and host != d for d in PAAS_LIST_EXP3):
            return 1
        return 0
    except Exception:
        return 0

# Construct high-link cloned phishing attacks on unlisted PaaS platforms
UNLISTED_PAAS_PHISH = [
    {"name": "Apple Lure on Replit", "url": "https://apple-login-security.replit.app/auth", "platform": "Replit (replit.app)", "links": 120},
    {"name": "Chase Lure on Fly.io", "url": "https://chase-bank-verify.fly.dev/login", "platform": "Fly.io (fly.dev)", "links": 95},
    {"name": "PayPal Lure on Railway", "url": "https://paypal-update-center.railway.app/signin", "platform": "Railway (railway.app)", "links": 110},
    {"name": "Microsoft Lure on CF Workers", "url": "https://microsoft-auth-sec.workers.dev/oauth2", "platform": "Cloudflare Workers (workers.dev)", "links": 80},
    {"name": "Netflix Lure on Deno Deploy", "url": "https://netflix-account-check.deno.dev/login.html", "platform": "Deno Deploy (deno.dev)", "links": 150},
    {"name": "Meta Lure on Cyclic", "url": "https://meta-business-suite.cyclic.app/verify", "platform": "Cyclic (cyclic.app)", "links": 90},
    {"name": "Binance Lure on Supabase", "url": "https://binance-wallet-auth.supabase.co/session", "platform": "Supabase (supabase.co)", "links": 85}
]

results = []
for item in UNLISTED_PAAS_PHISH:
    u = item["url"]
    uf = extract_url_features(u)
    hf = get_default_html_feature_dict(parse_error=False)
    hf["num_links"] = item["links"]
    hf["num_internal_links"] = int(item["links"] * 0.9)
    hf["num_external_links"] = item["links"] - hf["num_internal_links"]
    hf["external_link_ratio"] = float(hf["num_external_links"] / item["links"])
    hf["has_login_form"] = False # Cloned page where static form was not detected
    hf["uses_https"] = True
    
    # Base vector (Control)
    comb_base = {**uf, **hf}
    comb_base["url_parse_error"] = 0
    comb_base["html_parse_error"] = 0
    vec_base = pd.DataFrame([[comb_base.get(c, 0) for c in base_feature_cols]], columns=base_feature_cols)
    prob_prod = float(model_prod.predict_proba(vec_base)[0, 1])
    
    # Exp 3 vector
    comb_exp3 = dict(comb_base)
    comb_exp3["is_free_hosting_subdomain"] = get_paas_flag(u)
    vec_exp3 = pd.DataFrame([[comb_exp3.get(c, 0) for c in feat_cols_exp3]], columns=feat_cols_exp3)
    prob_exp3 = float(model_exp3.predict_proba(vec_exp3)[0, 1])
    
    results.append({
        "Attack Target": item["name"],
        "Platform": item["platform"],
        "On Feature Provider List?": "YES" if get_paas_flag(u) == 1 else "NO (Unlisted)",
        "Control Score": f"{prob_prod*100:.2f}% ({'Caught' if prob_prod >= 0.50 else 'MISSED'})",
        "Candidate Exp 3 Score": f"{prob_exp3*100:.2f}% ({'Caught' if prob_exp3 >= 0.50 else 'MISSED'})",
        "Delta": f"{(prob_exp3 - prob_prod)*100:+.2f}%"
    })

print("=" * 90)
print("GENERALIZATION CHECK ON UNLISTED FREE-HOSTING / PAAS PLATFORMS")
print("=" * 90)
df_res = pd.DataFrame(results)
print(df_res.to_string(index=False))
