from pathlib import Path
import pandas as pd
import hashlib
import urllib.parse

df_exp = pd.read_csv("backend/data/processed/training_dataset_expanded.csv")
df_div = pd.read_csv("backend/data/processed/diverse_legitimate_records.csv")

print(f"df_exp: {len(df_exp)} rows ({df_exp['label'].value_counts().to_dict()})")
print(f"df_div: {len(df_div)} rows ({df_div['label'].value_counts().to_dict()})")

# Check overlap of URLs between df_exp and df_div
overlap_urls = set(df_exp["url"]).intersection(set(df_div["url"]))
print(f"URL overlap between df_exp and df_div: {len(overlap_urls)}")

# Combine datasets and drop duplicates if any
df_combined = pd.concat([df_exp, df_div], ignore_index=True)
df_combined = df_combined.drop_duplicates(subset=["url"]).reset_index(drop=True)

print(f"Combined clean dataset: {len(df_combined)} rows")
print(f"Combined labels: {df_combined['label'].value_counts().to_dict()}")
