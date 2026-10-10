from pathlib import Path
import pandas as pd
import hashlib

cache_dir = Path("backend/data/raw/html_cache")
df_exp = pd.read_csv("backend/data/processed/training_dataset_expanded.csv")
df_div = pd.read_csv("backend/data/processed/diverse_legitimate_records.csv")

print(f"HTML cache dir exists: {cache_dir.exists()}")
if cache_dir.exists():
    cached_files = list(cache_dir.glob("*.html"))
    print(f"Total cached HTML files: {len(cached_files):,}")

# Check how many URLs in df_exp and df_div have cached HTML files
found_exp = 0
for u in df_exp["url"]:
    h = hashlib.sha256(u.strip().encode("utf-8")).hexdigest()
    if (cache_dir / f"{h}.html").exists():
        found_exp += 1

found_div = 0
for u in df_div["url"]:
    h = hashlib.sha256(u.strip().encode("utf-8")).hexdigest()
    if (cache_dir / f"{h}.html").exists():
        found_div += 1

print(f"df_exp cached HTML: {found_exp} / {len(df_exp)}")
print(f"df_div cached HTML: {found_div} / {len(df_div)}")
