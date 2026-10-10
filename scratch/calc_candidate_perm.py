import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.model_selection import GroupKFold

BACKEND_DIR = Path("backend").resolve()
MODELS_DIR = BACKEND_DIR / "ml" / "models"
CANDIDATES_DIR = MODELS_DIR / "candidates_link_density"
DATA_DIR = BACKEND_DIR / "data" / "processed"
HTML_CACHE_DIR = BACKEND_DIR / "data" / "raw" / "html_cache"

# Load candidate model & columns
candidate_model = joblib.load(CANDIDATES_DIR / "candidate_link_density_model.joblib")
with open(CANDIDATES_DIR / "candidate_feature_columns.json", "r") as f:
    feature_columns = json.load(f)

# Load dataset and prepare candidate features
df = pd.read_csv(DATA_DIR / "training_dataset_expanded.csv")
df_div = pd.read_csv(DATA_DIR / "diverse_legitimate_records.csv") if (DATA_DIR / "diverse_legitimate_records.csv").exists() else None
if df_div is not None:
    df = pd.concat([df, df_div], ignore_index=True).drop_duplicates(subset=["url"]).reset_index(drop=True)

df["label_binary"] = df["label"].map({"phishing": 1, "legitimate": 0, 1: 1, 0: 0}).astype(int)

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

df["internal_link_ratio"] = np.where(
    df["num_links"] > 0,
    np.clip(df["num_internal_links"].astype(float) / np.maximum(1.0, df["num_links"].astype(float)), 0.0, 1.0),
    0.0
)
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
df["link_density_per_kb_html"] = np.where(
    html_sizes_kb > 0.0,
    np.clip(df["num_links"].astype(float) / np.maximum(0.1, html_sizes_kb), 0.0, 50.0),
    0.0
)
df["links_per_form"] = np.where(
    df["num_forms"] > 0,
    np.clip(df["num_links"].astype(float) / df["num_forms"].astype(float), 0.0, 100.0),
    0.0
)
df["links_per_input_field"] = np.where(
    df["num_input_fields"] > 0,
    np.clip(df["num_links"].astype(float) / df["num_input_fields"].astype(float), 0.0, 100.0),
    0.0
)

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

df["subdomain_to_apex_length_ratio"] = [
    compute_subdomain_ratio(u, a) for u, a in zip(df["url"], df["registered_domain"])
]

gkf = GroupKFold(n_splits=5)
train_idx, test_idx = next(gkf.split(df, df["label_binary"], groups=df["registered_domain"]))
test_df = df.iloc[test_idx]

X_te = test_df[feature_columns].values
y_te = test_df["label_binary"].values

perm_res = permutation_importance(candidate_model, X_te, y_te, scoring="recall", n_repeats=5, random_state=42)

perm_report = [
    {
        "feature": feature_columns[i],
        "importance_mean": round(float(perm_res.importances_mean[i]), 6),
        "importance_std": round(float(perm_res.importances_std[i]), 6)
    }
    for i in range(len(feature_columns))
]
perm_report.sort(key=lambda x: x["importance_mean"], reverse=True)

with open(CANDIDATES_DIR / "candidate_permutation_importances.json", "w") as f:
    json.dump(perm_report, f, indent=2)

print("Saved permutation importances to candidate directory.")
print("Top 10 Permutation Features for Candidate C1:")
for p in perm_report[:10]:
    print(f"  {p['feature']}: mean={p['importance_mean']:.6f} (+/- {p['importance_std']:.6f})")
