"""Pipeline module to assemble, validate, and write the final tabular ML training dataset."""

import csv
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import pandas as pd

from ml.feature_extraction import (
    HTML_FEATURE_NAMES,
    URL_FEATURE_NAMES,
    extract_html_features,
    extract_url_features,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Paths
BACKEND_ROOT = Path(__file__).resolve().parents[2]
DATASET_MANIFEST_CSV = BACKEND_ROOT / "data" / "processed" / "dataset_manifest.csv"
TRAINING_DATASET_CSV = BACKEND_ROOT / "data" / "processed" / "training_dataset.csv"

# Canonical column ordering for the combined training dataset
TRAINING_COLUMNS: List[str] = [
    # Traceability & Labels
    "url",
    "label_binary",
    "label",
    # URL Features (Stage 3)
    *[("url_parse_error" if c == "parse_error" else c) for c in URL_FEATURE_NAMES],
    # HTML Features (Stage 4)
    *[("html_parse_error" if c == "parse_error" else c) for c in HTML_FEATURE_NAMES],
]


def assemble_single_record(
    url: str,
    label: str,
    html_content: str,
) -> Dict[str, Union[str, int, float]]:
    """Extract and combine URL and HTML features for a single sample into an ML-ready record.

    Args:
        url: Webpage URL string.
        label: Original label ('legitimate' or 'phishing').
        html_content: Raw HTML text content.

    Returns:
        Dictionary mapping column names in TRAINING_COLUMNS to values.
    """
    label_str = label.strip().lower()
    label_binary = 1 if label_str == "phishing" else 0

    url_feats = extract_url_features(url)
    html_feats = extract_html_features(html_content, page_url=url)

    row: Dict[str, Union[str, int, float]] = {
        "url": url,
        "label_binary": label_binary,
        "label": label_str,
    }

    # Append URL features (convert bools to 0/1 for ML numeric compatibility)
    for k, v in url_feats.items():
        col_name = "url_parse_error" if k == "parse_error" else k
        row[col_name] = int(v) if isinstance(v, bool) else v

    # Append HTML features (convert bools to 0/1)
    for k, v in html_feats.items():
        col_name = "html_parse_error" if k == "parse_error" else k
        row[col_name] = int(v) if isinstance(v, bool) else v

    return row


def _process_manifest_chunk(
    items: List[Tuple[int, Dict[str, str], Path]],
) -> Tuple[List[Tuple[int, Optional[Dict[str, Union[str, int, float]]]]], List[str]]:
    """Helper worker to process a batch/chunk of manifest rows across a process pool."""
    results: List[Tuple[int, Optional[Dict[str, Union[str, int, float]]]]] = []
    warnings_list: List[str] = []

    for idx, row, root in items:
        rel_html_path = row.get("html_file_path", "")
        if not rel_html_path:
            results.append((idx, None))
            continue

        html_file = root / "data" / rel_html_path
        if not html_file.exists() or html_file.stat().st_size == 0:
            warnings_list.append(f"Cached HTML file not found on disk: {html_file}")
            results.append((idx, None))
            continue

        try:
            html_content = html_file.read_text(encoding="utf-8", errors="replace")
        except Exception as read_exc:
            warnings_list.append(f"Failed to read HTML file {html_file}: {read_exc}")
            results.append((idx, None))
            continue

        try:
            record = assemble_single_record(
                url=row["url"],
                label=row["label"],
                html_content=html_content,
            )
            results.append((idx, record))
        except Exception as proc_exc:
            warnings_list.append(f"Error processing row {idx} ({row.get('url', '')}): {proc_exc}")
            results.append((idx, None))

    return results, warnings_list


def build_training_dataset(
    manifest_path: Path = DATASET_MANIFEST_CSV,
    output_path: Path = TRAINING_DATASET_CSV,
    base_dir: Optional[Path] = None,
    workers: Optional[int] = None,
) -> pd.DataFrame:
    """Build, validate, and persist the combined tabular ML training dataset.

    Args:
        manifest_path: Path to dataset_manifest.csv.
        output_path: Destination path for training_dataset.csv.
        base_dir: Base root directory for data file resolution (defaults to BACKEND_ROOT).
        workers: Concurrent worker processes (defaults to CPU count or 8).

    Returns:
        Assembled pandas DataFrame.
    """
    import os
    from concurrent.futures import ProcessPoolExecutor, as_completed

    root = base_dir if base_dir is not None else BACKEND_ROOT
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest file not found: {manifest_path}")

    logger.info("Reading manifest from %s...", manifest_path)

    skipped_unfetched = 0
    skipped_missing_file = 0
    total_manifest_rows = 0
    valid_rows: List[Dict[str, str]] = []

    with open(manifest_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_manifest_rows += 1
            if row.get("fetch_success") != "True":
                skipped_unfetched += 1
                continue
            valid_rows.append(row)

    num_workers = workers if workers is not None else min(8, os.cpu_count() or 4)
    logger.info(
        "Extracting features across %d successful rows using %d worker processes...",
        len(valid_rows),
        num_workers,
    )

    records: List[Optional[Dict[str, Union[str, int, float]]]] = [None] * len(valid_rows)

    # For tiny test batches, run sequentially in-process
    items = [(i, row, root) for i, row in enumerate(valid_rows)]
    if len(valid_rows) <= 20 or num_workers <= 1:
        chunk_results, warnings_list = _process_manifest_chunk(items)
        for warn_msg in warnings_list:
            logger.warning(warn_msg)
        for idx, res in chunk_results:
            if res is not None:
                records[idx] = res
            else:
                skipped_missing_file += 1
    else:
        chunk_size = max(50, (len(valid_rows) + num_workers - 1) // (num_workers * 4))
        chunks = [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]

        completed_samples = 0
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(_process_manifest_chunk, chunk) for chunk in chunks]
            for future in as_completed(futures):
                chunk_results, warnings_list = future.result()
                for warn_msg in warnings_list:
                    logger.warning(warn_msg)
                for idx, res in chunk_results:
                    if res is not None:
                        records[idx] = res
                    else:
                        skipped_missing_file += 1
                completed_samples += len(chunk_results)
                logger.info(
                    "Progress: %d / %d rows assembled (%.1f%%)...",
                    completed_samples,
                    len(valid_rows),
                    (completed_samples / len(valid_rows)) * 100,
                )

    # Filter out None values while preserving row ordering
    valid_records = [r for r in records if r is not None]

    logger.info(
        "Manifest scanning complete: %d total rows | %d included | %d unfetched | %d missing files",
        total_manifest_rows,
        len(valid_records),
        skipped_unfetched,
        skipped_missing_file,
    )

    df = pd.DataFrame(valid_records, columns=TRAINING_COLUMNS)

    # Persist to CSV
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False, encoding="utf-8")
    logger.info("Persisted final training dataset (%d rows, %d columns) to %s", len(df), len(df.columns), output_path)

    # -------------------------------------------------------------
    # Validation & Sanity Reporting
    # -------------------------------------------------------------
    total_rows = len(df)
    phish_count = int((df["label_binary"] == 1).sum())
    legit_count = int((df["label_binary"] == 0).sum())
    phish_pct = (phish_count / total_rows * 100) if total_rows > 0 else 0
    legit_pct = (legit_count / total_rows * 100) if total_rows > 0 else 0

    null_count = int(df.isnull().sum().sum())
    dup_count = int(df.duplicated(subset=["url"]).sum())

    # Compute correlations with label_binary
    corr_series = df.drop(columns=["url", "label"]).corr()["label_binary"].drop("label_binary")
    abs_corr = corr_series.abs().sort_values(ascending=False)

    url_cols_set = set([("url_parse_error" if c == "parse_error" else c) for c in URL_FEATURE_NAMES])
    html_cols_set = set([("html_parse_error" if c == "parse_error" else c) for c in HTML_FEATURE_NAMES])

    top_url_corr = corr_series[corr_series.index.isin(url_cols_set)].abs().sort_values(ascending=False).head(5)
    top_html_corr = corr_series[corr_series.index.isin(html_cols_set)].abs().sort_values(ascending=False).head(5)

    print("\n" + "=" * 70)
    print("            TRAINING DATASET ASSEMBLY & SANITY REPORT")
    print("=" * 70)
    print(f"Total Assembled Training Samples: {total_rows:,}")
    print(f"  - Legitimate Samples (label=0): {legit_count:,} ({legit_pct:.2f}%)")
    print(f"  - Phishing Samples   (label=1): {phish_count:,} ({phish_pct:.2f}%)")
    print(f"Total Columns:                   {len(df.columns)}")
    print(f"Missing / NaN Values Count:      {null_count}")
    print(f"Duplicate URLs Count:            {dup_count}")
    print("-" * 70)
    print("TOP 5 URL FEATURES (by Pearson correlation with label_binary):")
    for rank, (feat, val) in enumerate(top_url_corr.items(), 1):
        signed_val = corr_series[feat]
        print(f"  {rank}. {feat:<30} | r = {signed_val:+0.4f} (|r| = {val:0.4f})")

    print("\nTOP 5 HTML FEATURES (by Pearson correlation with label_binary):")
    for rank, (feat, val) in enumerate(top_html_corr.items(), 1):
        signed_val = corr_series[feat]
        print(f"  {rank}. {feat:<30} | r = {signed_val:+0.4f} (|r| = {val:0.4f})")
    print("=" * 70 + "\n")

    return df


if __name__ == "__main__":
    build_training_dataset()
