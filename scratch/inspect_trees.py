"""Inspect tree decision paths and feature contributions for ps.bitsathy.ac.in."""

import sys
from pathlib import Path
import pandas as pd
import numpy as np

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.core.model_loader import get_model, get_feature_columns
from ml.feature_extraction.url_features import extract_url_features
from ml.feature_extraction.html_features import extract_html_features
from app.services.detection_engine import DetectionEngine

TARGET_URL = "https://ps.bitsathy.ac.in"

engine = DetectionEngine()
success, html_content, _, _ = engine.fetch_single_html(TARGET_URL)

url_feats = extract_url_features(TARGET_URL)
html_feats = extract_html_features(html_content, TARGET_URL) if html_content else {}

combined_feats = {}
for k, v in url_feats.items():
    col = "url_parse_error" if k == "parse_error" else k
    combined_feats[col] = int(v) if isinstance(v, bool) else v

for k, v in html_feats.items():
    col = "html_parse_error" if k == "parse_error" else k
    combined_feats[col] = int(v) if isinstance(v, bool) else v

feature_cols = get_feature_columns()
df_sample = pd.DataFrame([[combined_feats[c] for c in feature_cols]], columns=feature_cols)

model = get_model()

# Let's inspect the booster's score contribution per feature or trees
booster = model.get_booster()

# Compare against a typical legitimate site (e.g. https://wikipedia.org or https://google.com)
benign_url = "https://en.wikipedia.org/wiki/Main_Page"
success_b, html_b, _, _ = engine.fetch_single_html(benign_url)
url_b = extract_url_features(benign_url)
html_b_feats = extract_html_features(html_b, benign_url)
combined_b = {}
for k, v in url_b.items():
    col = "url_parse_error" if k == "parse_error" else k
    combined_b[col] = int(v) if isinstance(v, bool) else v
for k, v in html_b_feats.items():
    col = "html_parse_error" if k == "parse_error" else k
    combined_b[col] = int(v) if isinstance(v, bool) else v

df_benign = pd.DataFrame([[combined_b[c] for c in feature_cols]], columns=feature_cols)

print(f"ps.bitsathy.ac.in proba: {model.predict_proba(df_sample)[0]}")
print(f"wikipedia proba: {model.predict_proba(df_benign)[0]}")

# Let's load the training dataset to see statistics of benign vs phishing on key features
dataset_path = BACKEND_DIR / "data" / "processed" / "training_dataset.csv"
if dataset_path.exists():
    df_train = pd.read_csv(dataset_path)
    print("\n--- Training Dataset Distribution Comparisons ---")
    key_features = [
        "num_links", "num_internal_links", "domain_length", "path_length",
        "num_subdomains", "num_dots", "num_slashes", "num_digits", "num_hyphens",
        "url_length", "num_images", "text_to_html_ratio", "num_scripts"
    ]
    for feat in key_features:
        if feat in df_train.columns:
            benign_mean = df_train[df_train['label'] == 0][feat].mean()
            benign_median = df_train[df_train['label'] == 0][feat].median()
            phish_mean = df_train[df_train['label'] == 1][feat].mean()
            phish_median = df_train[df_train['label'] == 1][feat].median()
            sample_val = combined_feats.get(feat)
            print(f"{feat:<20} | Sample: {sample_val:<6} | Benign Median: {benign_median:<6.1f} (Mean: {benign_mean:<6.1f}) | Phish Median: {phish_median:<6.1f} (Mean: {phish_mean:<6.1f})")

# Feature perturbation analysis: modify features one by one to see what drops the score below 0.30 (safe)
print("\n--- Sensitivity Analysis: What changes would make ps.bitsathy.ac.in classify as Safe? ---")
base_prob = model.predict_proba(df_sample)[0][1]

# Try varying different features
test_cases = [
    ("num_links = 50", {"num_links": 50}),
    ("num_internal_links = 40", {"num_internal_links": 40}),
    ("num_links=50 & num_internal_links=40", {"num_links": 50, "num_internal_links": 40}),
    ("domain_length = 10", {"domain_length": 10}),
    ("num_subdomains = 0", {"num_subdomains": 0}),
    ("num_dots = 1", {"num_dots": 1}),
    ("num_subdomains=0, num_dots=1", {"num_subdomains": 0, "num_dots": 1}),
    ("num_links=50, internal=40, num_subdomains=0, num_dots=1", {"num_links": 50, "num_internal_links": 40, "num_subdomains": 0, "num_dots": 1}),
    ("path_length = 30", {"path_length": 30}),
    ("num_digits = 0", {"num_digits": 0}),
    ("num_images = 10", {"num_images": 10}),
]

for desc, mods in test_cases:
    mod_df = df_sample.copy()
    for k, v in mods.items():
        mod_df[k] = v
    new_prob = model.predict_proba(mod_df)[0][1]
    print(f"{desc:<60} -> Phishing Prob: {new_prob:.4f} (Delta: {new_prob - base_prob:+.4f})")
