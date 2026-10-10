"""Orchestrate URL list acquisition and HTML fetching into a consolidated dataset manifest."""

import csv
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple

from ml.data_collection.config import (
    DATASET_MANIFEST_CSV,
    HTML_CACHE_DIR,
    LEGITIMATE_URLS_CSV,
    PHISHING_URLS_CSV,
    PROCESSED_DATA_DIR,
    RAW_DATA_DIR,
    TARGET_LEGITIMATE_CANDIDATES,
    TARGET_PHISHING_CANDIDATES,
)
from ml.data_collection.fetch_html import fetch_html_batch
from ml.data_collection.fetch_url_lists import (
    fetch_tranco_legitimate_urls,
    prepare_phishing_url_pool,
    save_url_list_to_csv,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

MANIFEST_FIELDNAMES = [
    "url",
    "label",
    "html_file_path",
    "http_status",
    "fetch_success",
    "fetch_timestamp",
    "source",
]


def load_existing_manifest() -> Tuple[List[Dict[str, object]], Set[str]]:
    """Load previously saved manifest records and processed URL set if manifest exists."""
    if not DATASET_MANIFEST_CSV.exists():
        return [], set()

    existing_rows: List[Dict[str, object]] = []
    processed_urls: Set[str] = set()

    try:
        with open(DATASET_MANIFEST_CSV, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                row["fetch_success"] = row.get("fetch_success", "").lower() == "true"
                existing_rows.append(row)
                processed_urls.add(row["url"])
        logger.info("Loaded %d previously processed entries from %s", len(existing_rows), DATASET_MANIFEST_CSV)
    except Exception as exc:
        logger.warning("Could not load existing manifest: %s", exc)

    return existing_rows, processed_urls


def save_manifest(records: List[Dict[str, object]]) -> None:
    """Write complete dataset manifest to CSV."""
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(DATASET_MANIFEST_CSV, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=MANIFEST_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records)
    logger.info("Saved %d total rows to manifest: %s", len(records), DATASET_MANIFEST_CSV)


def load_or_fetch_url_lists() -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Load candidate URL lists from CSV if already saved, otherwise fetch from source feeds."""
    legit_candidates: List[Dict[str, str]] = []
    phish_candidates: List[Dict[str, str]] = []

    if LEGITIMATE_URLS_CSV.exists():
        with open(LEGITIMATE_URLS_CSV, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            legit_candidates = list(reader)
        logger.info("Loaded %d legitimate candidate URLs from disk.", len(legit_candidates))
    else:
        logger.info("Downloading fresh legitimate URLs from Tranco...")
        legit_candidates = fetch_tranco_legitimate_urls(max_count=TARGET_LEGITIMATE_CANDIDATES)
        save_url_list_to_csv(legit_candidates, LEGITIMATE_URLS_CSV)

    if PHISHING_URLS_CSV.exists():
        with open(PHISHING_URLS_CSV, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            phish_candidates = list(reader)
        logger.info("Loaded %d phishing candidate URLs from disk.", len(phish_candidates))
    else:
        logger.info("Downloading fresh phishing URLs from PhishTank & OpenPhish...")
        phish_candidates = prepare_phishing_url_pool(max_count=TARGET_PHISHING_CANDIDATES)
        save_url_list_to_csv(phish_candidates, PHISHING_URLS_CSV)

    return legit_candidates, phish_candidates


def build_dataset(
    target_legitimate_success: int = 2600,
    target_phishing_success: int = 2600,
) -> None:
    """Orchestrate candidate harvesting and HTML fetching to build dataset.

    Args:
        target_legitimate_success: Target number of successfully fetched legitimate pages.
        target_phishing_success: Target number of successfully fetched phishing pages.
    """
    RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    HTML_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load candidate lists
    legit_candidates, phish_candidates = load_or_fetch_url_lists()

    # 2. Check existing manifest
    all_manifest_rows, processed_urls = load_existing_manifest()

    existing_legit_success = sum(
        1 for r in all_manifest_rows if r.get("label") == "legitimate" and r.get("fetch_success")
    )
    existing_phish_success = sum(
        1 for r in all_manifest_rows if r.get("label") == "phishing" and r.get("fetch_success")
    )

    logger.info(
        "Current existing successful fetches: Legitimate: %d/%d, Phishing: %d/%d",
        existing_legit_success,
        target_legitimate_success,
        existing_phish_success,
        target_phishing_success,
    )

    # 3. Fetch Legitimate HTML batch
    remaining_legit_needed = max(0, target_legitimate_success - existing_legit_success)
    if remaining_legit_needed > 0:
        logger.info("=== Fetching HTML for Legitimate URLs (Goal: %d) ===", remaining_legit_needed)
        new_legit_results = fetch_html_batch(
            candidate_records=legit_candidates,
            target_success=remaining_legit_needed,
            existing_processed_urls=processed_urls,
        )
        for r in new_legit_results:
            all_manifest_rows.append(r)
            processed_urls.add(str(r["url"]))
        save_manifest(all_manifest_rows)

    # 4. Fetch Phishing HTML batch
    remaining_phish_needed = max(0, target_phishing_success - existing_phish_success)
    if remaining_phish_needed > 0:
        logger.info("=== Fetching HTML for Phishing URLs (Goal: %d) ===", remaining_phish_needed)
        new_phish_results = fetch_html_batch(
            candidate_records=phish_candidates,
            target_success=remaining_phish_needed,
            existing_processed_urls=processed_urls,
        )
        for r in new_phish_results:
            all_manifest_rows.append(r)
            processed_urls.add(str(r["url"]))
        save_manifest(all_manifest_rows)

    # 5. Calculate and print detailed final summary
    total_candidates = len(all_manifest_rows)
    successful_legit = sum(
        1 for r in all_manifest_rows if r.get("label") == "legitimate" and r.get("fetch_success")
    )
    attempted_legit = sum(1 for r in all_manifest_rows if r.get("label") == "legitimate")

    successful_phish = sum(
        1 for r in all_manifest_rows if r.get("label") == "phishing" and r.get("fetch_success")
    )
    attempted_phish = sum(1 for r in all_manifest_rows if r.get("label") == "phishing")

    total_success = successful_legit + successful_phish
    overall_success_rate = (total_success / total_candidates * 100) if total_candidates > 0 else 0

    print("\n" + "=" * 65)
    print("           DATASET COLLECTION RUN SUMMARY")
    print("=" * 65)
    print(f"Total URL Candidates Attempted:  {total_candidates:,}")
    print(
        f"  - Legitimate URLs Attempted:   {attempted_legit:,} (Successful: {successful_legit:,} | "
        f"Rate: {(successful_legit/attempted_legit*100) if attempted_legit > 0 else 0:.1f}%)"
    )
    print(
        f"  - Phishing URLs Attempted:     {attempted_phish:,} (Successful: {successful_phish:,} | "
        f"Rate: {(successful_phish/attempted_phish*100) if attempted_phish > 0 else 0:.1f}%)"
    )
    print("-" * 65)
    print(f"Total Successful URL+HTML Pairs: {total_success:,}")
    print(f"Overall Fetch Success Rate:      {overall_success_rate:.2f}%")
    print(f"Dataset Manifest File:           {DATASET_MANIFEST_CSV}")
    print(f"HTML Cache Folder:               {HTML_CACHE_DIR}")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    build_dataset()
