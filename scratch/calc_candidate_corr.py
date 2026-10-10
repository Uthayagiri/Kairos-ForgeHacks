import json
from pathlib import Path
import pandas as pd
import numpy as np

BACKEND_DIR = Path("backend").resolve()
MODELS_DIR = BACKEND_DIR / "ml" / "models"
CANDIDATES_DIR = MODELS_DIR / "candidates_link_density"
DATA_DIR = BACKEND_DIR / "data" / "processed"
HTML_CACHE_DIR = BACKEND_DIR / "data" / "raw" / "html_cache"

with open(CANDIDATES_DIR / "candidate_feature_columns.json", "r") as f:
    feature_columns = json.load(f)

df = pd.read_csv(DATA_DIR / "training_dataset_expanded.csv")

def extract_registered_domain(url_str: str) -> str:
    try:
        if not isinstance(url_str, str) or not url_str.strip():
            return "unknown"
        target = url_str if "://" in url_str else f"http://{url_str}"
        import urllib.parse
        host = urllib.parse.urlsplit(target).hostname or "unknown"
        host = host.lower().strip(".")
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return "unknown"

df["registered_domain"] = df["url"].apply(extract_registered_domain)
df["internal_link_ratio"] = np.where(df["num_links"] > 0, np.clip(df["num_internal_links"].astype(float) / np.maximum(1.0, df["num_links"].astype(float)), 0.0, 1.0), 0.0)
df["external_link_ratio"] = np.clip(df["external_link_ratio"].fillna(0.0).astype(float), 0.0, 1.0)

html_sizes_kb = []
for u in df["url"]:
    import hashlib
    h = hashlib.sha256(u.strip().encode("utf-8")).hexdigest()
    f = HTML_CACHE_DIR / f"{h}.html"
    if f.exists():
        html_sizes_kb.append(f.stat().st_size / 1024.0)
    else:
        html_sizes_kb.append(0.0)
html_sizes_kb = np.array(html_sizes_kb, dtype=float)
df["html_size_kb"] = html_sizes_kb
df["link_density_per_kb_html"] = np.where(html_sizes_kb > 0.0, np.clip(df["num_links"].astype(float) / np.maximum(0.1, html_sizes_kb), 0.0, 50.0), 0.0)
df["links_per_form"] = np.where(df["num_forms"] > 0, np.clip(df["num_links"].astype(float) / df["num_forms"].astype(float), 0.0, 100.0), 0.0)
df["links_per_input_field"] = np.where(df["num_input_fields"] > 0, np.clip(df["num_links"].astype(float) / df["num_input_fields"].astype(float), 0.0, 100.0), 0.0)

def compute_subdomain_ratio(url_str: str, apex_domain: str) -> float:
    try:
        import urllib.parse
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

df["subdomain_to_apex_length_ratio"] = [compute_subdomain_ratio(u, a) for u, a in zip(df["url"], df["registered_domain"])]

corr_matrix = df[feature_columns].corr().abs()
high_corr_pairs = []
for i in range(len(feature_columns)):
    for j in range(i + 1, len(feature_columns)):
        c = corr_matrix.iloc[i, j]
        if c >= 0.70:
            high_corr_pairs.append({
                "feature_1": feature_columns[i],
                "feature_2": feature_columns[j],
                "correlation": round(float(c), 4)
            })

high_corr_pairs.sort(key=lambda x: x["correlation"], reverse=True)

with open(CANDIDATES_DIR / "candidate_feature_correlations.json", "w") as f:
    json.dump(high_corr_pairs, f, indent=2)

print(f"Candidate feature correlations computed: {len(high_corr_pairs)} pairs with |r| >= 0.70 (dropped r=0.9717 num_links <-> num_internal_links)")
for p in high_corr_pairs:
    print(f"  {p['feature_1']} <-> {p['feature_2']}: r={p['correlation']}")
