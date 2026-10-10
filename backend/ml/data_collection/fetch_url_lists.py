"""Download, validate, deduplicate, and prepare raw URL lists for legitimate and phishing sites."""

import csv
import io
import logging
import urllib.request
import zipfile
from typing import Dict, List, Set

from ml.data_collection.config import (
    LEGITIMATE_URLS_CSV,
    OPENPHISH_FEED_URL,
    PHISHING_URLS_CSV,
    PHISHTANK_CSV_URL,
    RAW_DATA_DIR,
    TARGET_LEGITIMATE_CANDIDATES,
    TARGET_PHISHING_CANDIDATES,
    TRANCO_LIST_URL,
    USER_AGENT,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def clean_url(url: str) -> str:
    """Normalize and clean URL string."""
    url = url.strip()
    if not url:
        return ""
    if not (url.startswith("http://") or url.startswith("https://")):
        url = f"https://{url}"
    return url


def fetch_tranco_legitimate_urls(max_count: int = TARGET_LEGITIMATE_CANDIDATES) -> List[Dict[str, str]]:
    """Download legitimate URLs from the Tranco Top Sites list.

    Args:
        max_count: Maximum number of candidate legitimate URLs to extract.

    Returns:
        List of dictionaries with keys: url, source, label
    """
    logger.info("Downloading Tranco Top 1M dataset from %s...", TRANCO_LIST_URL)
    headers = {"User-Agent": USER_AGENT}
    req = urllib.request.Request(TRANCO_LIST_URL, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            zip_bytes = resp.read()
    except Exception as exc:
        logger.error("Failed to download Tranco list: %s", exc)
        raise RuntimeError(f"Error downloading Tranco dataset from {TRANCO_LIST_URL}: {exc}") from exc

    results: List[Dict[str, str]] = []
    seen: Set[str] = set()

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        csv_filename = zf.namelist()[0]
        with zf.open(csv_filename) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            for row in reader:
                if not row or len(row) < 2:
                    continue
                domain = row[1].strip()
                if not domain:
                    continue
                url = clean_url(domain)
                if url and url not in seen:
                    seen.add(url)
                    results.append({"url": url, "source": "Tranco Top-1M", "label": "legitimate"})
                if len(results) >= max_count:
                    break

    logger.info("Extracted %d unique legitimate candidate URLs from Tranco.", len(results))
    return results


def fetch_openphish_urls() -> List[Dict[str, str]]:
    """Fetch phishing URLs from OpenPhish community feed."""
    logger.info("Fetching OpenPhish community feed from %s...", OPENPHISH_FEED_URL)
    headers = {"User-Agent": USER_AGENT}
    req = urllib.request.Request(OPENPHISH_FEED_URL, headers=headers)
    results: List[Dict[str, str]] = []

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            for line in resp:
                url_str = line.decode("utf-8", errors="ignore").strip()
                url = clean_url(url_str)
                if url:
                    results.append({"url": url, "source": "OpenPhish", "label": "phishing"})
        logger.info("Extracted %d URLs from OpenPhish.", len(results))
    except Exception as exc:
        logger.warning("Failed to fetch OpenPhish feed: %s", exc)

    return results


def fetch_phishtank_urls(max_count: int = TARGET_PHISHING_CANDIDATES) -> List[Dict[str, str]]:
    """Download verified active phishing URLs from PhishTank.

    Args:
        max_count: Maximum number of phishing URLs to extract.

    Returns:
        List of dictionaries with keys: url, source, label
    """
    logger.info("Downloading PhishTank verified online CSV from %s...", PHISHTANK_CSV_URL)
    headers = {"User-Agent": USER_AGENT}
    req = urllib.request.Request(PHISHTANK_CSV_URL, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
    except Exception as exc:
        logger.error("Failed to download PhishTank CSV: %s", exc)
        raise RuntimeError(f"Error downloading PhishTank dataset from {PHISHTANK_CSV_URL}: {exc}") from exc

    results: List[Dict[str, str]] = []
    reader = csv.reader(content.splitlines())
    header = next(reader, None)

    if not header or "url" not in header:
        raise ValueError("Invalid PhishTank CSV format: 'url' column not found")

    url_idx = header.index("url")
    for row in reader:
        if len(row) > url_idx:
            url = clean_url(row[url_idx])
            if url:
                results.append({"url": url, "source": "PhishTank", "label": "phishing"})
        if len(results) >= max_count:
            break

    logger.info("Extracted %d verified phishing URLs from PhishTank.", len(results))
    return results


def prepare_phishing_url_pool(max_count: int = TARGET_PHISHING_CANDIDATES) -> List[Dict[str, str]]:
    """Combine and deduplicate phishing URLs from OpenPhish and PhishTank."""
    openphish_list = fetch_openphish_urls()
    phishtank_list = fetch_phishtank_urls(max_count=max_count)

    seen: Set[str] = set()
    combined: List[Dict[str, str]] = []

    for item in openphish_list + phishtank_list:
        url = item["url"]
        if url not in seen:
            seen.add(url)
            combined.append(item)
        if len(combined) >= max_count:
            break

    logger.info("Combined and deduplicated total %d phishing candidate URLs.", len(combined))
    return combined


def save_url_list_to_csv(url_records: List[Dict[str, str]], output_path) -> None:
    """Save URL records to CSV file with columns: url, source, label."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "source", "label"])
        writer.writeheader()
        writer.writerows(url_records)
    logger.info("Saved %d records to %s", len(url_records), output_path)


def run_fetch_url_lists() -> None:
    """Orchestrate downloading and saving raw legitimate and phishing URL candidate pools."""
    RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("=== Step 1: Fetching Legitimate URL Candidates ===")
    legit_records = fetch_tranco_legitimate_urls(max_count=TARGET_LEGITIMATE_CANDIDATES)
    save_url_list_to_csv(legit_records, LEGITIMATE_URLS_CSV)

    logger.info("=== Step 2: Fetching Phishing URL Candidates ===")
    phishing_records = prepare_phishing_url_pool(max_count=TARGET_PHISHING_CANDIDATES)
    save_url_list_to_csv(phishing_records, PHISHING_URLS_CSV)

    logger.info(
        "Candidate URL harvesting complete! Total candidates: %d (Legitimate: %d, Phishing: %d)",
        len(legit_records) + len(phishing_records),
        len(legit_records),
        len(phishing_records),
    )


if __name__ == "__main__":
    run_fetch_url_lists()
