import os
import pandas as pd
from pathlib import Path

backend_dir = Path("backend")
processed_dir = backend_dir / "data" / "processed"
raw_dir = backend_dir / "data" / "raw"
cohort_dir = backend_dir / "data" / "young_domain_cohort"

print("--- Processed Files ---")
for p in processed_dir.glob("*"):
    if p.is_file():
        print(f"{p.name}: {p.stat().st_size:,} bytes")
        if p.suffix == ".csv":
            df = pd.read_csv(p)
            print(f"  Shape: {df.shape}, Columns: {list(df.columns[:8])}...")
            if "label" in df.columns:
                print(f"  Labels: {df['label'].value_counts().to_dict()}")

print("\n--- Cohort Files ---")
for p in cohort_dir.glob("*"):
    if p.is_file():
        print(f"{p.name}: {p.stat().st_size:,} bytes")
        if p.suffix == ".csv":
            try:
                df = pd.read_csv(p)
                print(f"  Shape: {df.shape}, Columns: {list(df.columns[:8])}...")
            except Exception as e:
                print(f"  Error reading CSV: {e}")

print("\n--- Raw Files ---")
for p in raw_dir.glob("*"):
    if p.is_file():
        print(f"{p.name}: {p.stat().st_size:,} bytes")
