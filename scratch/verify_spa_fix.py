"""Verification script for SPA shell false positive fix."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.services.detection_engine import DetectionEngine
from ml.feature_extraction.html_features import (
    extract_html_features,
    is_likely_unrendered_spa_shell,
)
from ml.feature_extraction.html_feature_config import (
    SPA_SHELL_MAX_FORMS,
    SPA_SHELL_MAX_IMAGES,
    SPA_SHELL_MAX_LINKS,
    SPA_SHELL_MAX_TEXT_RATIO,
    SPA_SHELL_MIN_SCRIPTS,
)

def run_tests():
    print("============================================================")
    print("STAGE 8.1 SPA-SHELL FALSE POSITIVE FIX VERIFICATION")
    print("============================================================\n")

    engine = DetectionEngine()

    # 1. Live Test: ps.bitsathy.ac.in
    print("--- 1. Live Test: https://ps.bitsathy.ac.in ---")
    res_ps = engine.analyze_url("https://ps.bitsathy.ac.in")
    print(f"Status: {res_ps.status}")
    print(f"Risk Level: {res_ps.risk_level}")
    print(f"Confidence (Adjusted): {res_ps.confidence}")
    print(f"HTML Available: {res_ps.html_available}")
    print(f"Content Rendering Incomplete: {res_ps.content_rendering_incomplete}")
    print(f"Indicators:")
    for ind in res_ps.detected_indicators:
        print(f"  - {ind}")

    assert res_ps.status in ("safe", "suspicious"), f"Expected safe/suspicious, got {res_ps.status}"
    assert res_ps.risk_level in ("low", "medium"), f"Expected low/medium, got {res_ps.risk_level}"
    assert res_ps.confidence <= 0.48, f"Expected confidence <= 0.48, got {res_ps.confidence}"
    assert res_ps.content_rendering_incomplete is True
    print("\n[OK] ps.bitsathy.ac.in successfully dampened from 81.9% High Phishing to Bounded/Medium!")

    # 2. Mock SPA Shell on Clean URL vs Malicious URL
    print("\n--- 2. Mock SPA Shell Pattern Tests ---")
    mock_spa_html = """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8"/>
        <title>App Portal</title>
        <script src="/static/bundle.js"></script>
        <script src="/static/vendors.js"></script>
      </head>
      <body>
        <div id="root"></div>
      </body>
    </html>
    """

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_content.return_value = [mock_spa_html.encode("utf-8")]

    # 2a. Clean URL with SPA HTML
    with patch.object(engine.session, "get", return_value=mock_resp):
        res_clean_spa = engine.analyze_url("https://portal.myuniversity.edu/student")
        print(f"Clean SPA -> Status: {res_clean_spa.status}, Risk: {res_clean_spa.risk_level}, Conf: {res_clean_spa.confidence}, Incomplete: {res_clean_spa.content_rendering_incomplete}")
        assert res_clean_spa.status in ("safe", "suspicious")
        assert res_clean_spa.risk_level in ("low", "medium")
        assert res_clean_spa.confidence <= 0.48
        assert res_clean_spa.content_rendering_incomplete is True

    # 2b. Strong Malicious URL with SPA HTML (e.g. attacker hosting minimal JS redirection/shell)
    with patch.object(engine.session, "get", return_value=mock_resp):
        res_phish_spa = engine.analyze_url("http://192.168.1.1/paypal/login.php")
        print(f"Malicious SPA (Raw IP + Login) -> Status: {res_phish_spa.status}, Risk: {res_phish_spa.risk_level}, Conf: {res_phish_spa.confidence}, Incomplete: {res_phish_spa.content_rendering_incomplete}")
        assert res_phish_spa.status == "phishing"
        assert res_phish_spa.risk_level == "high"
        assert res_phish_spa.confidence >= 0.70
        assert res_phish_spa.content_rendering_incomplete is True
        print("[OK] Threat-driven escalation maintained on malicious URL with SPA shell!")

    # 3. Genuine Sparse Static Phishing Page (0 links, NO scripts, minimal HTML)
    print("\n--- 3. Genuinely Sparse Static Phishing Page (NO Scripts) ---")
    mock_sparse_static_phish = """
    <!DOCTYPE html>
    <html>
      <head><title>Urgent Security Notice</title></head>
      <body>
        <p>Your account is locked. Call 1-800-XXX or click below to verify.</p>
      </body>
    </html>
    """
    mock_resp_sparse = MagicMock()
    mock_resp_sparse.status_code = 200
    mock_resp_sparse.headers = {"Content-Type": "text/html"}
    mock_resp_sparse.encoding = "utf-8"
    mock_resp_sparse.iter_content.return_value = [mock_sparse_static_phish.encode("utf-8")]

    # Check is_likely_unrendered_spa_shell directly
    sparse_feats = extract_html_features(mock_sparse_static_phish, "http://fake-alert.com")
    is_spa = is_likely_unrendered_spa_shell(sparse_feats)
    print(f"Sparse static HTML has num_scripts={sparse_feats.get('num_scripts')}. is_likely_unrendered_spa_shell: {is_spa}")
    assert is_spa is False, "Sparse static page with NO scripts must NOT be identified as an SPA shell!"

    # 4. Standard Legitimate Site with rich HTML
    print("\n--- 4. Standard Legitimate Site ---")
    mock_rich_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Wikipedia - Free Encyclopedia</title></head>
      <body>
        <a href="/wiki/A">Link 1</a>
        <a href="/wiki/B">Link 2</a>
        <a href="/wiki/C">Link 3</a>
        <img src="/logo.png"/>
        <p>Lots of legitimate content and text explaining topics in detail.</p>
        <script src="/analytics.js"></script>
      </body>
    </html>
    """
    rich_feats = extract_html_features(mock_rich_html, "https://wikipedia.org")
    assert is_likely_unrendered_spa_shell(rich_feats) is False
    print("[OK] Rich multi-link legitimate page not flagged as SPA shell.")

    print("\n============================================================")
    print("ALL VERIFICATION ASSERTIONS PASSED! [OK]")
    print("============================================================\n")

if __name__ == "__main__":
    run_tests()
