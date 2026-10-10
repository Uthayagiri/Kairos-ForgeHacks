"""Fetch live HTML content for candidate URLs with robust safety, timeouts, and caching."""

import csv
import hashlib
import logging
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests

from ml.data_collection.config import (
    HTML_CACHE_DIR,
    LOG_PROGRESS_INTERVAL,
    MAX_RESPONSE_BYTES,
    MAX_WORKERS,
    REQUEST_DELAY_MAX,
    REQUEST_DELAY_MIN,
    REQUEST_TIMEOUT,
    USER_AGENT,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def get_url_hash(url: str) -> str:
    """Compute SHA-256 hex digest for a given URL string."""
    return hashlib.sha256(url.strip().encode("utf-8")).hexdigest()


def get_cache_file_path(url: str) -> Path:
    """Return local HTML cache file path for a URL."""
    url_hash = get_url_hash(url)
    return HTML_CACHE_DIR / f"{url_hash}.html"


def fetch_html_for_url(
    url: str,
    label: str,
    source: str,
    session: Optional[requests.Session] = None,
    save_cache: bool = True,
) -> Dict[str, object]:
    """Perform a guarded HTTP GET to fetch webpage HTML content.

    Args:
        url: Webpage URL to fetch.
        label: Dataset label ('legitimate' or 'phishing').
        source: Originating data source name.
        session: Optional persistent requests.Session instance.
        save_cache: If True, writes successful HTML to disk cache.

    Returns:
        Dict with keys: url, label, html_file_path, http_status,
        fetch_success, fetch_timestamp, source, error_reason
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    cache_path = get_cache_file_path(url)

    # If cached file already exists on disk, treat as success
    if cache_path.exists() and cache_path.stat().st_size > 0:
        return {
            "url": url,
            "label": label,
            "html_file_path": str(cache_path.relative_to(HTML_CACHE_DIR.parent.parent)),
            "http_status": 200,
            "fetch_success": True,
            "fetch_timestamp": timestamp,
            "source": source,
            "error_reason": "cached",
        }

    # Small jitter delay to prevent hammering servers
    delay = random.uniform(REQUEST_DELAY_MIN, REQUEST_DELAY_MAX)
    time.sleep(delay)

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }

    req_client = session if session is not None else requests

    try:
        response = req_client.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            stream=True,
            verify=False,  # Avoid crashing on expired/self-signed SSL certificates in phishing sites
            allow_redirects=True,
        )

        http_status = response.status_code

        # Reject non-200 responses
        if http_status != 200:
            return {
                "url": url,
                "label": label,
                "html_file_path": "",
                "http_status": http_status,
                "fetch_success": False,
                "fetch_timestamp": timestamp,
                "source": source,
                "error_reason": f"HTTP {http_status}",
            }

        # Check content type header (must be HTML)
        content_type = response.headers.get("Content-Type", "").lower()
        if content_type and not any(ht in content_type for ht in ["text/html", "application/xhtml+xml", "text/plain"]):
            return {
                "url": url,
                "label": label,
                "html_file_path": "",
                "http_status": http_status,
                "fetch_success": False,
                "fetch_timestamp": timestamp,
                "source": source,
                "error_reason": f"Non-HTML Content-Type: {content_type}",
            }

        # Stream content up to MAX_RESPONSE_BYTES limit
        content_chunks = []
        bytes_read = 0

        for chunk in response.iter_content(chunk_size=65536):
            if chunk:
                bytes_read += len(chunk)
                if bytes_read > MAX_RESPONSE_BYTES:
                    return {
                        "url": url,
                        "label": label,
                        "html_file_path": "",
                        "http_status": http_status,
                        "fetch_success": False,
                        "fetch_timestamp": timestamp,
                        "source": source,
                        "error_reason": f"Response exceeds size limit ({bytes_read} bytes)",
                    }
                content_chunks.append(chunk)

        raw_bytes = b"".join(content_chunks)
        if not raw_bytes or len(raw_bytes.strip()) == 0:
            return {
                "url": url,
                "label": label,
                "html_file_path": "",
                "http_status": http_status,
                "fetch_success": False,
                "fetch_timestamp": timestamp,
                "source": source,
                "error_reason": "Empty HTML body",
            }

        # Decode content with fallback
        encoding = response.encoding or "utf-8"
        try:
            html_text = raw_bytes.decode(encoding, errors="replace")
        except Exception:
            html_text = raw_bytes.decode("utf-8", errors="replace")

        # Save to cache with physical write verification
        if save_cache:
            try:
                HTML_CACHE_DIR.mkdir(parents=True, exist_ok=True)
                cache_path.write_text(html_text, encoding="utf-8", errors="replace")
                if not cache_path.exists() or cache_path.stat().st_size == 0:
                    return {
                        "url": url,
                        "label": label,
                        "html_file_path": "",
                        "http_status": http_status,
                        "fetch_success": False,
                        "fetch_timestamp": timestamp,
                        "source": source,
                        "error_reason": "Cache file write verification failed",
                    }
            except Exception as write_err:
                return {
                    "url": url,
                    "label": label,
                    "html_file_path": "",
                    "http_status": http_status,
                    "fetch_success": False,
                    "fetch_timestamp": timestamp,
                    "source": source,
                    "error_reason": f"Disk I/O error during cache write: {write_err}",
                }

        return {
            "url": url,
            "label": label,
            "html_file_path": str(cache_path.relative_to(HTML_CACHE_DIR.parent.parent)),
            "http_status": http_status,
            "fetch_success": True,
            "fetch_timestamp": timestamp,
            "source": source,
            "error_reason": "",
        }


    except requests.exceptions.Timeout:
        return {
            "url": url,
            "label": label,
            "html_file_path": "",
            "http_status": None,
            "fetch_success": False,
            "fetch_timestamp": timestamp,
            "source": source,
            "error_reason": "Request timeout",
        }
    except requests.exceptions.SSLError as ssl_err:
        return {
            "url": url,
            "label": label,
            "html_file_path": "",
            "http_status": None,
            "fetch_success": False,
            "fetch_timestamp": timestamp,
            "source": source,
            "error_reason": f"SSL Error: {ssl_err}",
        }
    except requests.exceptions.ConnectionError:
        return {
            "url": url,
            "label": label,
            "html_file_path": "",
            "http_status": None,
            "fetch_success": False,
            "fetch_timestamp": timestamp,
            "source": source,
            "error_reason": "Connection error / DNS resolution failure",
        }
    except Exception as exc:
        return {
            "url": url,
            "label": label,
            "html_file_path": "",
            "http_status": None,
            "fetch_success": False,
            "fetch_timestamp": timestamp,
            "source": source,
            "error_reason": f"General fetch error: {exc}",
        }


def fetch_html_batch(
    candidate_records: List[Dict[str, str]],
    target_success: Optional[int] = None,
    max_workers: int = MAX_WORKERS,
    existing_processed_urls: Optional[Set[str]] = None,
) -> List[Dict[str, object]]:
    """Fetch HTML for a batch of candidate URLs concurrently.

    Args:
        candidate_records: List of dicts containing url, source, label.
        target_success: Stop once this many successful fetches are achieved.
        max_workers: Number of concurrent threads.
        existing_processed_urls: Set of URLs previously completed (to skip).

    Returns:
        List of result dictionaries.
    """
    HTML_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    results: List[Dict[str, object]] = []
    processed_urls = existing_processed_urls or set()

    to_process = [rec for rec in candidate_records if rec["url"] not in processed_urls]
    logger.info(
        "Starting concurrent HTML fetch for %d candidates (Target successes: %s, Workers: %d)...",
        len(to_process),
        str(target_success) if target_success else "All",
        max_workers,
    )

    success_count = 0
    total_attempted = 0

    # Suppress InsecureRequestWarning when verifying untrusted SSL certificates for phishing URLs
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(
                fetch_html_for_url,
                rec["url"],
                rec["label"],
                rec["source"],
            ): rec["url"]
            for rec in to_process
        }

        for future in as_completed(future_map):
            try:
                res = future.result()
                results.append(res)
                total_attempted += 1
                if res["fetch_success"]:
                    success_count += 1

                if total_attempted % LOG_PROGRESS_INTERVAL == 0 or (
                    target_success and success_count >= target_success
                ):
                    logger.info(
                        "Progress: %d attempted | %d successful | Current batch success rate: %.2f%%",
                        total_attempted,
                        success_count,
                        (success_count / total_attempted) * 100 if total_attempted > 0 else 0,
                    )

                if target_success and success_count >= target_success:
                    logger.info("Reached target success count (%d). Concluding batch.", target_success)
                    # Cancel pending futures
                    for pending in future_map:
                        pending.cancel()
                    break

            except Exception as exc:
                logger.error("Unexpected worker exception: %s", exc)

    logger.info(
        "Batch fetch finished: %d attempted, %d successful.",
        total_attempted,
        success_count,
    )
    return results
