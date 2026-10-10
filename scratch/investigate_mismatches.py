"""Detailed Root Cause Investigation for the 3 Mismatches in Part A."""

import json
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

from ml.feature_extraction import extract_url_features, extract_html_features
from app.services.detection_engine import DetectionEngine

engine = DetectionEngine()

mismatches = [
    "https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7095405/",
    "https://tinyurl.com/app",
    "https://example.com/?redirect=https%3A%2F%2Fother.com%2Fpath%3Fparam%3Dval",
]

print("=" * 80)
print("INVESTIGATING MISMATCHES")
print("=" * 80)

for url in mismatches:
    print(f"\n--- URL: {url} ---")
    res = engine.analyze_url(url)
    print(f"Status: {res.status}, Risk: {res.risk_level}, Conf: {res.confidence:.4f}, Phish: {res.is_phishing}")
    print(f"HTML Available: {res.html_available}, SPA Incomplete: {res.content_rendering_incomplete}")
    print(f"Indicators: {res.detected_indicators}")
    print(f"URL Features: {json.dumps(res.url_features_summary, indent=2)}")

