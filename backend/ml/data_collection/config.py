"""Configuration constants for data collection and HTML fetching."""

from pathlib import Path

# Paths (relative to backend root)
BACKEND_ROOT = Path(__file__).resolve().parents[2]
RAW_DATA_DIR = BACKEND_ROOT / "data" / "raw"
PROCESSED_DATA_DIR = BACKEND_ROOT / "data" / "processed"
HTML_CACHE_DIR = RAW_DATA_DIR / "html_cache"

LEGITIMATE_URLS_CSV = RAW_DATA_DIR / "legitimate_urls.csv"
PHISHING_URLS_CSV = RAW_DATA_DIR / "phishing_urls.csv"
DATASET_MANIFEST_CSV = PROCESSED_DATA_DIR / "dataset_manifest.csv"

# Source URLs
TRANCO_LIST_URL = "https://tranco-list.eu/top-1m.csv.zip"
PHISHTANK_CSV_URL = "https://data.phishtank.com/data/online-valid.csv"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"

# Candidate pool target sizes
TARGET_LEGITIMATE_CANDIDATES = 15000
TARGET_PHISHING_CANDIDATES = 22000

# HTML fetch parameters
REQUEST_TIMEOUT = 6  # seconds
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB cap
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Concurrency & pacing settings
MAX_WORKERS = 36
REQUEST_DELAY_MIN = 0.05  # seconds
REQUEST_DELAY_MAX = 0.15  # seconds
LOG_PROGRESS_INTERVAL = 100

# Note on Rate-Limiting Architecture (Limitation documented for Stage 14):
# The delay (REQUEST_DELAY_MIN to REQUEST_DELAY_MAX) is applied per worker thread as randomized
# jitter rather than via a global per-domain lock/bucket. This is safe and effective here because
# input candidate URLs are heavily distributed across tens of thousands of distinct domains
# (Tranco has 1 URL per domain, and PhishTank URLs span varied hosts). However, under high
# worker concurrency (15-36 threads), if a candidate list were to contain multiple URLs on the
# exact same host, requests to that host could occur in close temporal proximity.

