"""Merge diverse legitimate dataset records with existing training dataset.

Deduplicates by URL and identical feature vectors, removes conflicting rows,
and exports the expanded, balanced training dataset.
"""

import csv
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

# Paths
BACKEND_DIR = Path("backend")
DATA_DIR = BACKEND_DIR / "data" / "processed"
ORIGINAL_CSV = DATA_DIR / "training_dataset.csv"
DIVERSE_CSV = DATA_DIR / "diverse_legitimate_records.csv"
EXPANDED_CSV = DATA_DIR / "training_dataset_expanded.csv"


def extract_registered_domain(url: str) -> str:
    """Extract registered domain (approximate 2-level or 3-level domain)."""
    try:
        if not (url.startswith("http://") or url.startswith("https://")):
            url = "http://" + url
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower().strip()
        if ":" in host:
            host = host.split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        
        two_part_tlds = {"co.uk", "ac.uk", "gov.uk", "ac.in", "gov.in", "co.in", "edu.in", "com.au", "net.au", "co.jp", "com.br", "co.za"}
        last_two = f"{parts[-2]}.{parts[-1]}"
        if last_two in two_part_tlds and len(parts) >= 3:
            return f"{parts[-3]}.{last_two}"
        
        return f"{parts[-2]}.{parts[-1]}"
    except Exception:
        return url


def merge_datasets():
    print("=" * 80)
    print("MERGING & EXPANDING TRAINING DATASET")
    print("=" * 80)

    orig_df = pd.read_csv(ORIGINAL_CSV)
    diverse_df = pd.read_csv(DIVERSE_CSV)

    print(f"Original dataset rows: {len(orig_df)}")
    print(f"Diverse legitimate rows: {len(diverse_df)}")

    # Combine
    combined_df = pd.concat([orig_df, diverse_df], ignore_index=True)
    print(f"Combined total before deduplication: {len(combined_df)}")

    # Deduplicate by URL
    combined_df = combined_df.drop_duplicates(subset=["url"], keep="first")
    print(f"After URL deduplication: {len(combined_df)}")

    # Check for duplicate feature vectors
    feature_cols = [c for c in combined_df.columns if c not in ("url", "label", "label_binary", "registered_domain")]
    
    # Drop near-duplicate rows with identical feature vectors AND same label
    combined_df = combined_df.drop_duplicates(subset=feature_cols + ["label_binary"], keep="first")
    print(f"After feature-vector deduplication: {len(combined_df)}")

    # Resolve any conflicting labels (if same features have both 0 and 1)
    label_conflicts = combined_df.groupby(feature_cols)["label_binary"].nunique()
    conflicting_feature_hashes = label_conflicts[label_conflicts > 1].index
    if len(conflicting_feature_hashes) > 0:
        print(f"Found {len(conflicting_feature_hashes)} conflicting feature signatures. Removing ambiguous rows...")
        # Remove ambiguous rows
        # create temporary tuple series
        feat_tuples = combined_df[feature_cols].apply(tuple, axis=1)
        conflicting_set = set(conflicting_feature_hashes)
        combined_df = combined_df[~feat_tuples.isin(conflicting_set)]

    # Add registered domain
    combined_df["registered_domain"] = combined_df["url"].apply(extract_registered_domain)

    print(f"\nFinal Clean Expanded Dataset: {len(combined_df)} rows across {combined_df['registered_domain'].nunique()} unique domains")
    print(f"Class Breakdown:\n{combined_df['label'].value_counts()}")
    print(f"Imbalance ratio: {(combined_df['label_binary']==0).sum() / (combined_df['label_binary']==1).sum():.4f}")

    # Inspect link distributions
    legit = combined_df[combined_df["label_binary"] == 0]
    phish = combined_df[combined_df["label_binary"] == 1]
    print(f"\nLegitimate link count quantiles: {legit['num_links'].quantile([0.05, 0.1, 0.25, 0.5, 0.75, 0.9]).to_dict()}")
    print(f"Phishing link count quantiles:   {phish['num_links'].quantile([0.05, 0.1, 0.25, 0.5, 0.75, 0.9]).to_dict()}")
    print(f"Legitimate sparse links (<=10): {(legit['num_links'] <= 10).sum()} / {len(legit)} ({(legit['num_links'] <= 10).sum()/len(legit)*100:.2f}%)")

    # Save expanded dataset
    # Drop registered_domain before saving to keep exact training columns format, or keep registered_domain as helper
    combined_df.to_csv(EXPANDED_CSV, index=False)
    print(f"\nSaved expanded dataset to: {EXPANDED_CSV}")
    print("=" * 80)


if __name__ == "__main__":
    merge_datasets()
