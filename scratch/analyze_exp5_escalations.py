"""Analyze Candidate Exp 5 escalation events and held-out ambiguous samples."""

import json
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

REPO_ROOT = Path("c:/Users/Udhaya/S5_Phishing_Detector").resolve()
BACKEND_DIR = REPO_ROOT / "backend"
DATASET_PATH = BACKEND_DIR / "data" / "processed" / "training_dataset.csv"
MODEL_PATH = BACKEND_DIR / "ml" / "models" / "phishing_model.joblib"
FEATURE_COLS_PATH = BACKEND_DIR / "ml" / "models" / "feature_columns.json"
EXP_LOG_FILE = REPO_ROOT / "scratch" / "exp5_escalation_events.log"

def extract_apex(url):
    try:
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
        host = urlparse(url).netloc.split(":")[0].lower().strip()
        if host.startswith("www."):
            host = host[4:]
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        two_part_tlds = {
            "co.uk", "ac.uk", "gov.uk", "ac.in", "gov.in", "co.in", "edu.in",
            "com.au", "net.au", "co.jp", "com.br", "co.za"
        }
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in two_part_tlds and len(parts) >= 3:
            return f"{parts[-3]}.{last_two}"
        return f"{parts[-2]}.{parts[-1]}"
    except Exception:
        return url

df = pd.read_csv(DATASET_PATH)
df["registered_domain"] = df["url"].apply(extract_apex)
feature_cols = json.load(open(FEATURE_COLS_PATH))
model = joblib.load(MODEL_PATH)

gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(gss.split(df, groups=df["registered_domain"]))
test_df = df.iloc[test_idx].copy()

X_test = test_df[feature_cols]
y_test = test_df["label_binary"].values
y_prob = model.predict_proba(X_test)[:, 1]
test_df["p_base"] = y_prob

ambig_mask = (test_df["p_base"] >= 0.35) & (test_df["p_base"] <= 0.70)
ambig = test_df[ambig_mask].copy()

print("=" * 90)
print(f"Total Dataset Size: {len(df)} samples across {df['registered_domain'].nunique()} unique domains")
print(f"Test Set Size:      {len(test_df)} samples across {test_df['registered_domain'].nunique()} unique domains")
print(f"Ambiguous Samples:  {len(ambig)} / {len(test_df)} ({len(ambig)/len(test_df)*100:.2f}%)")
print(f"  - True Phishing in Ambiguous Band:   {(ambig['label_binary'] == 1).sum()} samples")
print(f"  - True Legitimate in Ambiguous Band: {(ambig['label_binary'] == 0).sum()} samples")
print("=" * 90)

# Check distribution of p_base around 0.50 threshold
below_thresh = ambig[(ambig["p_base"] >= 0.35) & (ambig["p_base"] < 0.50)]
above_thresh = ambig[(ambig["p_base"] >= 0.50) & (ambig["p_base"] <= 0.70)]
print(f"\nAmbiguous Band Split around 0.50 decision boundary:")
print(f"  - [0.35, 0.50) (Classified as SAFE by base model):     {len(below_thresh)} samples (Legit: {(below_thresh['label_binary']==0).sum()}, Phish: {(below_thresh['label_binary']==1).sum()})")
print(f"  - [0.50, 0.70] (Classified as PHISHING by base model): {len(above_thresh)} samples (Legit: {(above_thresh['label_binary']==0).sum()}, Phish: {(above_thresh['label_binary']==1).sum()})")

# Specifically inspect the phishing samples in [0.35, 0.50) that could theoretically flip to TP if delta is added
print(f"\nPhishing samples in [0.35, 0.50) zone (potential FN -> TP flips):")
for idx, r in below_thresh[below_thresh["label_binary"] == 1].iterrows():
    p = r["p_base"]
    p_plus = p + 0.05
    flip = "YES (Flipped to >=0.50)" if p_plus >= 0.50 else "NO (Still <0.50)"
    print(f"  - URL: {r['url'][:55]:<55} | p_base: {p:.4f} | p+0.05: {p_plus:.4f} | Flip? {flip} | Domain: {r['registered_domain']}")

# Check full dataset for hosting types / domain sources
print("\n" + "=" * 90)
print("ANALYSIS OF DOMAIN TYPES & DATASET SOURCING (WHOLE DATASET & TEST SET)")
print("=" * 90)

# PaaS / Free hosting domains vs Standalone domains
PAAS_DOMAINS = {
    "pages.dev", "netlify.app", "github.io", "vercel.app", "firebaseapp.com",
    "render.com", "glitch.me", "surge.sh", "blogspot.com", "wordpress.com",
    "wixsite.com", "weebly.com", "000webhostapp.com", "sites.google.com",
    "s3.amazonaws.com", "blob.core.windows.net", "dub.sh", "replit.app",
    "fly.dev", "railway.app", "deno.dev", "web.app"
}

def is_paas(dom):
    return dom in PAAS_DOMAINS

df["is_paas"] = df["registered_domain"].apply(is_paas)
test_df["is_paas"] = test_df["registered_domain"].apply(is_paas)
ambig["is_paas"] = ambig["registered_domain"].apply(is_paas)

print(f"PaaS / Shared-Domain prevalence in Ambiguous Zone:")
print(f"  - Total Ambiguous Samples: {len(ambig)}")
print(f"  - PaaS-Hosted: {ambig['is_paas'].sum()} ({(ambig['is_paas'].mean()*100):.2f}%)")
print(f"  - Standalone Apex Domains: {(~ambig['is_paas']).sum()} ({((~ambig['is_paas']).mean()*100):.2f}%)")

print("\nLog file check (scratch/exp5_escalation_events.log):")
if EXP_LOG_FILE.exists():
    with open(EXP_LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    print(f"  - Total entries logged in exp5_escalation_events.log: {len(lines)}")
    for line in lines:
        try:
            entry = json.loads(line)
            print(f"    * URL: {entry.get('url')} | Domain: {entry.get('domain')} | p_base: {entry.get('p_base')} | RDAP Age: {entry.get('rdap_age_days')}d | Delta: {entry.get('delta')} | p_final: {entry.get('p_final')} | Status: {entry.get('infrastructure_status')}")
        except:
            pass
else:
    print("  - Log file not found.")
