from pathlib import Path
import pandas as pd
import numpy as np
import hashlib
import urllib.parse

cache_dir = Path("backend/data/raw/html_cache")
df = pd.read_csv("backend/data/processed/training_dataset_expanded.csv")

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

# 1. internal_link_ratio
df["internal_link_ratio"] = np.where(
    df["num_links"] > 0,
    np.clip(df["num_internal_links"] / np.maximum(1.0, df["num_links"].astype(float)), 0.0, 1.0),
    0.0
)

# 2. external_link_ratio (ensure clipped [0, 1])
df["external_link_ratio"] = np.clip(df["external_link_ratio"].fillna(0.0).astype(float), 0.0, 1.0)

# 3. link_density_per_kb_html
html_sizes_kb = []
for u in df["url"]:
    h = hashlib.sha256(u.strip().encode("utf-8")).hexdigest()
    f = cache_dir / f"{h}.html"
    if f.exists():
        html_sizes_kb.append(f.stat().st_size / 1024.0)
    else:
        html_sizes_kb.append(0.0)

html_sizes_kb = np.array(html_sizes_kb, dtype=float)
df["html_size_kb"] = html_sizes_kb
df["link_density_per_kb_html"] = np.where(
    html_sizes_kb > 0.0,
    np.clip(df["num_links"].astype(float) / np.maximum(0.1, html_sizes_kb), 0.0, 50.0),
    0.0
)

# 4. links_per_form
df["links_per_form"] = np.where(
    df["num_forms"] > 0,
    np.clip(df["num_links"].astype(float) / df["num_forms"].astype(float), 0.0, 100.0),
    0.0
)

# 5. links_per_input_field
df["links_per_input_field"] = np.where(
    df["num_input_fields"] > 0,
    np.clip(df["num_links"].astype(float) / df["num_input_fields"].astype(float), 0.0, 100.0),
    0.0
)

# 6. subdomain_to_apex_length_ratio
sub_ratios = []
for u, apex in zip(df["url"], df["registered_domain"] if "registered_domain" in df.columns else df["url"].apply(extract_registered_domain)):
    try:
        target = u if "://" in u else f"http://{u}"
        host = (urllib.parse.urlsplit(target).hostname or "").lower().strip(".")
        apex_str = str(apex).lower().strip(".")
        if host and apex_str and host != apex_str and host.endswith(apex_str):
            sub_part = host[:-len(apex_str)].rstrip(".")
            sub_len = len(sub_part)
        else:
            sub_len = 0
        r = min(10.0, round(float(sub_len / max(1, len(apex_str))), 4))
        sub_ratios.append(r)
    except Exception:
        sub_ratios.append(0.0)

df["subdomain_to_apex_length_ratio"] = sub_ratios

new_features = [
    "internal_link_ratio",
    "external_link_ratio",
    "link_density_per_kb_html",
    "links_per_form",
    "links_per_input_field",
    "subdomain_to_apex_length_ratio"
]

print("--- Candidate Features Summary ---")
for f in new_features:
    s = df[f]
    print(f"{f}: min={s.min():.4f}, max={s.max():.4f}, mean={s.mean():.4f}, nulls={s.isnull().sum()}, infs={np.isinf(s).sum()}")
    print(f"   Legit mean={df[df['label_binary']==0][f].mean():.4f} vs Phish mean={df[df['label_binary']==1][f].mean():.4f}")
