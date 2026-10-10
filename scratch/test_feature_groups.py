import json
import urllib.parse
from pathlib import Path
import numpy as np
import pandas as pd

DATA_DIR = Path("backend/data/processed")
df = pd.read_csv(DATA_DIR / "training_dataset_expanded.csv")
df["label_binary"] = df["label"].map({"phishing": 1, "legitimate": 0, 1: 1, 0: 0}).astype(int)

def extract_registered_domain(url_str: str) -> str:
    try:
        if not isinstance(url_str, str) or not url_str.strip():
            return "unknown"
        target = url_str if "://" in url_str else f"http://{url_str}"
        host = urllib.parse.urlsplit(target).hostname or "unknown"
        host = host.lower().strip(".")
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return "unknown"

def compute_subdomain_ratio(url_str: str, apex_domain: str) -> float:
    try:
        target = url_str if "://" in url_str else f"http://{url_str}"
        host = (urllib.parse.urlsplit(target).hostname or "").lower().strip(".")
        apex_str = str(apex_domain).lower().strip(".")
        if host and apex_str and host != apex_str and host.endswith(apex_str):
            sub_part = host[:-len(apex_str)].rstrip(".")
            sub_len = len(sub_part)
        else:
            sub_len = 0
        return min(10.0, round(float(sub_len / max(1, len(apex_str))), 4))
    except Exception:
        return 0.0

df["registered_domain"] = df["url"].apply(extract_registered_domain)

# -----------------------------------------------------------------
# Group B: Form Behavior Features
# -----------------------------------------------------------------
df["has_external_form_action"] = (df["num_forms_with_external_action"] > 0).astype(int)
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

# -----------------------------------------------------------------
# Group C: Page Structure Features
# -----------------------------------------------------------------
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

# -----------------------------------------------------------------
# Group D: URL/Content Consistency Features
# -----------------------------------------------------------------
df["subdomain_to_apex_length_ratio"] = [
    compute_subdomain_ratio(u, a) for u, a in zip(df["url"], df["registered_domain"])
]
df["suspicious_keyword_and_login_form"] = (
    (df["has_suspicious_keywords"] == 1) & (df["has_login_form"] == 1)
).astype(int)
df["high_external_link_concentration"] = (df["external_link_ratio"] > 0.75).astype(int)
df["mismatched_text_link_ratio"] = np.where(
    df["num_links"] > 0,
    np.clip(df["num_links_with_mismatched_text"].astype(float) / np.maximum(1.0, df["num_links"].astype(float)), 0.0, 1.0),
    0.0
)
df["shortened_and_credential_lure"] = (
    (df["is_shortened_url"] == 1) & 
    ((df["has_login_form"] == 1) | (df["has_suspicious_keywords"] == 1) | (df["num_password_fields"] > 0))
).astype(int)
df["brand_keyword_deep_path"] = (
    (df["has_suspicious_keywords"] == 1) & (df["path_depth"] >= 2)
).astype(int)

feature_groups = {
    "Group_B_Form_Behavior": [
        "has_external_form_action",
        "password_field_present",
        "external_form_action_ratio",
        "credential_collection_pattern",
    ],
    "Group_C_Page_Structure": [
        "meta_refresh_present",
        "script_to_link_ratio",
        "hidden_element_indicator",
        "iframe_to_image_ratio",
    ],
    "Group_D_URL_Content_Consistency": [
        "subdomain_to_apex_length_ratio",
        "suspicious_keyword_and_login_form",
        "high_external_link_concentration",
        "mismatched_text_link_ratio",
        "shortened_and_credential_lure",
        "brand_keyword_deep_path",
    ]
}

print("=== FEATURE GROUP STATISTICS (Legitimate vs Phishing) ===")
for g_name, g_cols in feature_groups.items():
    print(f"\n--- {g_name} ---")
    for col in g_cols:
        legit_m = df[df["label_binary"] == 0][col].mean()
        phish_m = df[df["label_binary"] == 1][col].mean()
        print(f"  {col:35s}: Legit={legit_m:.4f} | Phish={phish_m:.4f} | Ratio={phish_m / max(1e-5, legit_m):.2f}x")
