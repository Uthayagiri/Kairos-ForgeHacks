"""Module to crawl, extract, and fetch internal deep links from cached legitimate homepages.

Augments the legitimate URL class with realistic internal subpage URLs to eliminate
the path_length=0 domain-level shortcut bias.
"""

import csv
import logging
import random
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import lxml.html
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from ml.data_collection.config import HTML_CACHE_DIR, MAX_WORKERS, PROCESSED_DATA_DIR
from ml.data_collection.fetch_html import fetch_html_batch

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DATASET_MANIFEST_CSV = BACKEND_ROOT / "data" / "processed" / "dataset_manifest.csv"


def get_clean_host(url: str) -> str:
    """Extract clean lowercase hostname without port or www prefix."""
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower().strip()
    if ":" in host:
        host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host


def is_internal_link(base_url: str, target_url: str) -> bool:
    """Check whether target_url belongs to the same registered domain or subdomain as base_url."""
    base_host = get_clean_host(base_url)
    target_host = get_clean_host(target_url)

    if not base_host or not target_host:
        return False

    return target_host == base_host or target_host.endswith("." + base_host)


def extract_internal_deep_links(
    html_content: str,
    base_url: str,
    min_path_length: int = 1,
) -> List[str]:
    """Extract, resolve, and filter unique internal deep links from raw HTML content.

    Args:
        html_content: Raw HTML text of the homepage.
        base_url: Absolute URL of the homepage (e.g. 'https://wikipedia.org').
        min_path_length: Minimum character length of the relative path after stripping slashes.

    Returns:
        List of unique, absolute internal URLs with non-empty paths.
    """
    if not html_content or not base_url:
        return []

    raw_hrefs: List[str] = []

    # Fast C-based link extraction using lxml.html
    try:
        doc = lxml.html.fromstring(html_content)
        for element, attribute, link, pos in doc.iterlinks():
            if element.tag == "a" and attribute == "href" and link:
                raw_hrefs.append(link)
    except Exception:
        # Fallback to BeautifulSoup if lxml.html cannot parse
        try:
            soup = BeautifulSoup(html_content, "lxml")
            for a_tag in soup.find_all("a", href=True):
                raw_hrefs.append(a_tag["href"])
        except Exception:
            return []

    valid_links: Set[str] = set()

    for href in raw_hrefs:
        href_str = href.strip()

        # Skip empty, anchor, javascript, and mailto/tel links
        if not href_str or href_str.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "irc:")):
            continue

        # Resolve relative links
        try:
            resolved_url = urljoin(base_url, href_str)
        except Exception:
            continue

        parsed = urlparse(resolved_url)
        if parsed.scheme.lower() not in ("http", "https"):
            continue

        clean_url = f"{parsed.scheme.lower()}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean_url += f"?{parsed.query}"

        # Must have a real non-root path
        stripped_path = parsed.path.strip("/")
        if len(stripped_path) < min_path_length:
            continue

        # Must belong to the same internal domain
        if not is_internal_link(base_url, clean_url):
            continue

        # Skip common binary/media extensions
        lower_path = parsed.path.lower()
        if any(lower_path.endswith(ext) for ext in [".pdf", ".zip", ".tar", ".gz", ".exe", ".png", ".jpg", ".jpeg", ".mp4", ".mp3", ".svg", ".gif", ".css", ".js"]):
            continue

        valid_links.add(clean_url)

    return sorted(list(valid_links))


def _process_single_homepage(
    base_url: str,
    html_file: Path,
    samples_per_domain: int,
    seed: int,
) -> List[str]:
    """Helper worker to parse a single homepage HTML file and sample internal links."""
    try:
        html_text = html_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    links = extract_internal_deep_links(html_text, base_url)
    if not links:
        return []

    rng = random.Random(seed)
    rng.shuffle(links)
    return links[:samples_per_domain]


def gather_candidate_deep_links(
    manifest_path: Path = DATASET_MANIFEST_CSV,
    samples_per_domain: int = 2,
    random_state: int = 42,
    base_dir: Optional[Path] = None,
    parse_workers: int = 24,
) -> List[Dict[str, str]]:
    """Scan existing legitimate homepages concurrently and collect candidate internal deep links.

    Args:
        manifest_path: Path to dataset_manifest.csv.
        samples_per_domain: Maximum number of internal deep links to sample per homepage domain.
        random_state: Random seed for deterministic sampling.
        base_dir: Base directory for data path resolution.
        parse_workers: Concurrent workers for HTML parsing.

    Returns:
        List of candidate record dictionaries with keys: 'url', 'label', 'source'.
    """
    root = base_dir if base_dir is not None else BACKEND_ROOT
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    # Gather list of valid homepage files
    items_to_parse: List[Tuple[str, Path, int]] = []
    with open(manifest_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            if row.get("label") != "legitimate" or row.get("fetch_success") != "True":
                continue

            rel_html_path = row.get("html_file_path", "")
            if not rel_html_path:
                continue

            html_file = root / "data" / rel_html_path
            if not html_file.exists() or html_file.stat().st_size == 0:
                continue

            items_to_parse.append((row["url"], html_file, random_state + idx))

    logger.info("Parsing %d cached legitimate homepages across %d workers...", len(items_to_parse), parse_workers)

    candidates: List[Dict[str, str]] = []
    seen_urls: Set[str] = set()

    with ThreadPoolExecutor(max_workers=parse_workers) as executor:
        future_map = {
            executor.submit(_process_single_homepage, url, h_file, samples_per_domain, seed): url
            for url, h_file, seed in items_to_parse
        }

        for future in as_completed(future_map):
            base_url = future_map[future]
            try:
                sampled_links = future.result()
                for link_url in sampled_links:
                    if link_url not in seen_urls and link_url != base_url:
                        seen_urls.add(link_url)
                        candidates.append({
                            "url": link_url,
                            "label": "legitimate",
                            "source": "tranco_internal_link_crawl",
                        })
            except Exception as exc:
                logger.debug("Failed parsing %s: %s", base_url, exc)

    logger.info(
        "Gathered %d unique candidate legitimate deep-link URLs.",
        len(candidates),
    )
    return candidates


def crawl_and_append_deep_links(
    manifest_path: Path = DATASET_MANIFEST_CSV,
    samples_per_domain: int = 2,
    max_workers: int = MAX_WORKERS,
    random_state: int = 42,
    base_dir: Optional[Path] = None,
) -> Dict[str, int]:
    """Execute end-to-end deep-link crawling, HTML fetching, and manifest updating.

    Args:
        manifest_path: Path to dataset_manifest.csv.
        samples_per_domain: Links to sample per domain.
        max_workers: Concurrent workers for fetching HTML.
        random_state: Random seed.
        base_dir: Base directory.

    Returns:
        Summary counts dictionary.
    """
    candidates = gather_candidate_deep_links(
        manifest_path=manifest_path,
        samples_per_domain=samples_per_domain,
        random_state=random_state,
        base_dir=base_dir,
    )

    if not candidates:
        logger.warning("No candidate deep links found.")
        return {"attempted": 0, "successful": 0}

    # Fetch HTML concurrently
    logger.info("Fetching live HTML content for %d candidate deep links with %d workers...", len(candidates), max_workers)
    fetch_results = fetch_html_batch(
        candidate_records=candidates,
        max_workers=max_workers,
    )

    # Append to manifest
    fieldnames = [
        "url",
        "label",
        "html_file_path",
        "http_status",
        "fetch_success",
        "fetch_timestamp",
        "source",
    ]

    successful_count = 0
    with open(manifest_path, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        for res in fetch_results:
            writer.writerow(res)
            if res.get("fetch_success"):
                successful_count += 1

    logger.info(
        "Appended %d deep-link fetch records (%d successful) to %s.",
        len(fetch_results),
        successful_count,
        manifest_path,
    )

    return {
        "attempted": len(fetch_results),
        "successful": successful_count,
    }


if __name__ == "__main__":
    crawl_and_append_deep_links()
