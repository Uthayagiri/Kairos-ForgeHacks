"""Comprehensive integration tests for enhanced API endpoints and SSRF guards."""

import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_api_health(client: TestClient):
    """Test GET /api/health and GET /health."""
    res1 = client.get("/health")
    assert res1.status_code == 200
    assert res1.json() == {"status": "ok"}

    res2 = client.get("/api/health")
    assert res2.status_code == 200
    assert res2.json()["status"] == "ok"


def test_api_analyze_safe(client: TestClient):
    """Test POST /api/analyze with legitimate domain."""
    payload = {"url": "https://en.wikipedia.org/wiki/Computer_security"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("safe", "suspicious")
    assert "risk_score" in data
    assert "recommended_action" in data
    assert "model_version" in data
    assert "signals_breakdown" in data
    assert "uses_https" in data["url_features_summary"]


def test_api_analyze_ssrf_ip_block(client: TestClient):
    """Test POST /api/analyze with private/loopback IP to verify SSRF protection."""
    payload = {"url": "http://127.0.0.1:8080/admin/login"}
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    # SSRF guard should prevent live fetch
    assert data["html_available"] is False
    assert any("SSRF Guard" in ind or "raw IP" in ind.lower() for ind in data["detected_indicators"])


def test_api_history_and_stats(client: TestClient):
    """Test GET /api/history, GET /api/stats, and POST /api/history/clear."""
    # Analyze a test URL
    client.post("/api/analyze", json={"url": "https://example.com"})

    # Check history
    hist_res = client.get("/api/history?limit=10")
    assert hist_res.status_code == 200
    records = hist_res.json()
    assert isinstance(records, list)
    assert len(records) > 0

    # Check stats
    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "total_scans" in stats
    assert stats["total_scans"] >= 1
    assert "safe_count" in stats

    # Clear history
    clear_res = client.post("/api/history/clear")
    assert clear_res.status_code == 200
    assert clear_res.json()["status"] == "cleared"
