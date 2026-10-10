"""Test real, live, reachable JavaScript Single Page Applications (SPAs)."""

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.services.detection_engine import DetectionEngine
from ml.feature_extraction import extract_html_features, extract_url_features, is_likely_unrendered_spa_shell
from ml.training.tune_and_finalize_model import predict_phishing_sample
from app.core.model_loader import get_model, get_feature_columns

CANDIDATES = [
    "https://ps.bitsathy.ac.in",
    "https://excalidraw.com",
    "https://app.netlify.com",
    "https://linear.app",
    "https://trello.com",
    "https://open.spotify.com",
    "https://app.diagrams.net",
    "https://codesandbox.io",
    "https://web.whatsapp.com",
    "https://app.clickup.com",
    "https://react.dev",
]

def evaluate_candidates():
    engine = DetectionEngine(fetch_timeout=8.0)
    model = get_model()
    feature_columns = get_feature_columns()

    print("============================================================")
    print("LIVE REAL-WORLD JAVASCRIPT SPA TESTING")
    print("============================================================\n")

    for url in CANDIDATES:
        print(f"Testing URL: {url}")
        fetch_ok, html_content, err_msg, ssl_err = engine.fetch_single_html(url)
        if not fetch_ok or not html_content:
            print(f"  [FETCH FAILED] {err_msg} (Skipping)\n")
            continue

        url_feats = extract_url_features(url)
        html_feats = extract_html_features(html_content, page_url=url)
        is_spa = is_likely_unrendered_spa_shell(html_feats)

        # Assemble features for raw model prediction
        combined_features = {}
        for k, v in url_feats.items():
            col = "url_parse_error" if k == "parse_error" else k
            combined_features[col] = int(v) if isinstance(v, bool) else v
        for k, v in html_feats.items():
            col = "html_parse_error" if k == "parse_error" else k
            combined_features[col] = int(v) if isinstance(v, bool) else v

        pred = predict_phishing_sample(combined_features, model, feature_columns)
        raw_prob = float(pred["phishing_probability"])
        raw_is_phish = bool(pred["is_phishing"])

        # Run full engine (with fix)
        result = engine.analyze_url(url)

        print(f"  Fetch bytes: {len(html_content)}")
        print(f"  HTML features: links={html_feats.get('num_links')}, forms={html_feats.get('num_forms')}, images={html_feats.get('num_images')}, scripts={html_feats.get('num_scripts')}, text_ratio={html_feats.get('text_to_html_ratio')}")
        print(f"  is_likely_unrendered_spa_shell: {is_spa}")
        print(f"  RAW Model Output (Before Fix): prob={raw_prob:.4f}, is_phishing={raw_is_phish}")
        print(f"  ENGINE Output (After Fix): status={result.status}, risk={result.risk_level}, conf={result.confidence:.4f}, content_rendering_incomplete={result.content_rendering_incomplete}")
        print(f"  Indicators: {result.detected_indicators}")
        print("-" * 60)

if __name__ == "__main__":
    evaluate_candidates()
