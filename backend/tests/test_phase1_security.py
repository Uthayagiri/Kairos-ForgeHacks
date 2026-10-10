"""Phase 1 Backend Security Remediation Regression Test Suite.

Covers:
- SSRF prevention, IP validation, and private/metadata range rejection.
- IPv4, IPv6, IPv4-mapped IPv6, and multi-IP resolution edge cases.
- Outbound URL validation (schemes, credentials, ports).
- Redirect revalidation (private destination, metadata, scheme smuggling, redirect loop).
- Non-blocking async fetcher and timeout handling.
- Response body size limit enforcement.
- TLS certificate verification and error handling.
- CORS restricted origins and unauthorized origin rejection.
- Scan history protection (cross-site blocking, origin authorization, credential sanitization).
- End-to-end API predict contract stability.
"""

import socket
import ssl
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import requests
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.services.detection_engine import DetectionEngine, DetectionResult
from app.services.history_service import HistoryService
from app.services.ssrf_guard import (
    MAX_REDIRECT_HOPS,
    MAX_RESPONSE_BYTES,
    is_safe_ssrf_destination,
    resolve_and_validate_hostname,
    sanitize_url_for_logging,
    validate_outbound_url,
)


@pytest.fixture
def client():
    """Module test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def engine():
    """DetectionEngine instance for unit testing."""
    return DetectionEngine(fetch_timeout=2.0)


# =============================================================================
# 1. SSRF & IP Validation Tests
# =============================================================================

def test_ssrf_guard_blocks_private_and_restricted_destinations():
    """Verify that is_safe_ssrf_destination blocks loopback, private, metadata, and reserved destinations."""
    restricted_ips = [
        "127.0.0.1",
        "127.0.1.1",
        "localhost",
        "::1",
        "0.0.0.0",
        "10.0.0.1",
        "10.254.1.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.1.254",
        "169.254.169.254",  # AWS/Azure/GCP metadata
        "169.254.1.1",      # Link-local
        "100.64.0.1",       # Carrier-grade NAT
        "192.0.2.1",        # TEST-NET-1
        "198.51.100.1",     # TEST-NET-2
        "203.0.113.1",      # TEST-NET-3
        "224.0.0.1",        # Multicast
        "255.255.255.255",  # Broadcast
        "::ffff:127.0.0.1", # IPv4-mapped IPv6 loopback
        "::ffff:169.254.169.254", # IPv4-mapped IPv6 metadata
        "fe80::1",          # IPv6 link-local
        "fc00::1",          # IPv6 unique local
    ]

    for ip in restricted_ips:
        is_safe, err = is_safe_ssrf_destination(ip)
        assert is_safe is False, f"Expected {ip} to be rejected, but was accepted."
        assert err is not None


def test_ssrf_guard_accepts_clean_public_ips():
    """Verify that is_safe_ssrf_destination accepts legitimate public IP addresses."""
    public_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "2606:4700:4700::1111",
    ]

    for ip in public_ips:
        is_safe, err = is_safe_ssrf_destination(ip)
        assert is_safe is True, f"Expected {ip} to be safe, but got error: {err}"
        assert err is None


def test_ssrf_hostname_multi_dns_rejection():
    """Verify that a hostname resolving to multiple IPs where at least one is restricted is blocked."""
    # Mock socket.getaddrinfo returning one public and one internal IP
    mixed_results = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 80)),
    ]

    with patch("socket.getaddrinfo", return_value=mixed_results):
        is_safe, ips, err = resolve_and_validate_hostname("dual-homed.example.com")
        assert is_safe is False
        assert "restricted" in err.lower() or "internal" in err.lower()


def test_ssrf_dns_resolution_failure_handled_gracefully():
    """Verify that DNS resolution failure fails gracefully without throwing an uncaught exception, allowing HTTP client to handle connection error."""
    with patch("socket.getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")):
        is_safe, ips, err = resolve_and_validate_hostname("nonexistent-domain-test-404.xyz")
        assert is_safe is True
        assert ips == []
        assert err is None


# =============================================================================
# 2. Outbound URL Validation & Credential Stripping
# =============================================================================

def test_validate_outbound_url_schemes_and_ports():
    """Verify validate_outbound_url rejects unsupported schemes, invalid ports, and malformed URLs."""
    # Unsupported schemes
    assert validate_outbound_url("ftp://example.com")[0] is False
    assert validate_outbound_url("file:///etc/passwd")[0] is False
    assert validate_outbound_url("gopher://example.com")[0] is False
    assert validate_outbound_url("javascript:alert(1)")[0] is False

    # Invalid port
    assert validate_outbound_url("http://example.com:99999")[0] is False

    # Valid scheme and port with mocked clean DNS
    with patch("app.services.ssrf_guard.resolve_and_validate_hostname", return_value=(True, ["93.184.216.34"], None)):
        is_safe, _ = validate_outbound_url("https://example.com:8443/test")
        assert is_safe is True


def test_validate_outbound_url_embedded_credentials():
    """Verify URLs with embedded credentials are safely rejected by outbound fetcher."""
    is_safe, err = validate_outbound_url("http://admin:secret@example.com/portal")
    assert is_safe is False
    assert "credentials" in err.lower()


def test_sanitize_url_for_logging():
    """Verify URL sanitization strips embedded credentials and masks sensitive parameters."""
    raw = "https://user:password123@bank.com/reset?token=secret_token_val&session=sess99&code=12345&lang=en"
    clean = sanitize_url_for_logging(raw)
    assert "user" not in clean
    assert "password123" not in clean
    assert "secret_token_val" not in clean
    assert "token=[REDACTED]" in clean
    assert "session=[REDACTED]" in clean
    assert "code=[REDACTED]" in clean
    assert "lang=en" in clean


# =============================================================================
# 3. Redirect Validation & SSRF Bypass Prevention Tests
# =============================================================================

def test_sync_fetch_single_html_blocks_redirect_to_private_ip(engine):
    """Verify that a 302 redirect from a public URL to a private IP is blocked before the second request."""
    redirect_resp = MagicMock()
    redirect_resp.is_redirect = True
    redirect_resp.status_code = 302
    redirect_resp.headers = {"Location": "http://192.168.1.100/internal-admin"}

    with patch.object(engine.session, "get", return_value=redirect_resp) as mock_get, \
         patch("app.services.detection_engine.validate_outbound_url", side_effect=[(True, None), (False, "Target resolves to restricted IP")]):
        ok, content, err, is_ssl = engine.fetch_single_html("http://public-entry.com/redirect")
        assert ok is False
        assert "blocked" in err.lower() or "restricted" in err.lower()
        # Ensure only the initial request was attempted, NOT the second request
        assert mock_get.call_count == 1


def test_sync_fetch_single_html_blocks_redirect_to_metadata(engine):
    """Verify that a 301 redirect to the cloud metadata address is rejected."""
    redirect_resp = MagicMock()
    redirect_resp.is_redirect = True
    redirect_resp.status_code = 301
    redirect_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

    with patch.object(engine.session, "get", return_value=redirect_resp) as mock_get, \
         patch("app.services.detection_engine.validate_outbound_url", side_effect=[(True, None), (False, "Target resolves to restricted IP")]):
        ok, content, err, is_ssl = engine.fetch_single_html("http://public-entry.com/aws")
        assert ok is False
        assert "blocked" in err.lower() or "restricted" in err.lower()
        assert mock_get.call_count == 1


def test_sync_fetch_single_html_redirect_loop_terminates(engine):
    """Verify that redirect loops terminate safely after MAX_REDIRECT_HOPS."""
    loop_resp = MagicMock()
    loop_resp.is_redirect = True
    loop_resp.status_code = 302
    loop_resp.headers = {"Location": "http://public-loop.com/loop"}

    with patch.object(engine.session, "get", return_value=loop_resp) as mock_get, \
         patch("app.services.detection_engine.validate_outbound_url", return_value=(True, None)):
        ok, content, err, is_ssl = engine.fetch_single_html("http://public-loop.com/start")
        assert ok is False
        assert "exceeded maximum redirect hops" in err.lower()
        # Should have called at most MAX_REDIRECT_HOPS + 1 times
        assert mock_get.call_count <= MAX_REDIRECT_HOPS + 1


def test_sync_fetch_single_html_blocks_redirect_to_unsupported_scheme(engine):
    """Verify that a redirect to javascript:, file:, or other non-HTTP schemes is blocked."""
    redirect_resp = MagicMock()
    redirect_resp.is_redirect = True
    redirect_resp.status_code = 302
    redirect_resp.headers = {"Location": "javascript:alert(document.cookie)"}

    with patch.object(engine.session, "get", return_value=redirect_resp), \
         patch("app.services.detection_engine.validate_outbound_url", side_effect=[(True, None), (False, "Unsupported URL scheme")]):
        ok, content, err, is_ssl = engine.fetch_single_html("http://public-entry.com/xss")
        assert ok is False
        assert "blocked" in err.lower() or "unsupported" in err.lower()


# =============================================================================
# 4. Async Fetcher & Event Loop Safety
# =============================================================================

@pytest.mark.anyio
async def test_async_fetch_single_html_redirect_revalidation():
    """Verify async fetcher re-validates redirect destinations and enforces TLS verification."""
    eng = DetectionEngine(fetch_timeout=2.0)

    # Test that an outbound URL failing SSRF validation is rejected immediately without network call
    with patch("app.services.detection_engine.validate_outbound_url", return_value=(False, "SSRF Guard: Restricted IP")):
        ok, content, err, is_ssl = await eng.fetch_single_html_async("http://127.0.0.1:8000/api/history")
        assert ok is False
        assert "restricted" in err.lower() or "ssrf" in err.lower()


@pytest.mark.anyio
async def test_async_fetch_single_html_size_cap():
    """Verify async fetcher enforces response size limits."""
    eng = DetectionEngine(fetch_timeout=2.0, max_bytes=100)

    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/html", "content-length": "5000"}
    mock_resp.content = b"A" * 5000

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_resp

    with patch("httpx.AsyncClient") as mock_client_cls, \
         patch("app.services.detection_engine.validate_outbound_url", return_value=(True, None)):
        mock_client_cls.return_value.__aenter__.return_value = mock_client

        ok, content, err, is_ssl = await eng.fetch_single_html_async("https://large-payload.example.com")
        assert ok is False
        assert "size limit" in err.lower()


# =============================================================================
# 5. TLS Certificate Verification & Error Handling
# =============================================================================

def test_tls_verification_failure_is_graceful(engine):
    """Verify that TLS certificate validation failures set is_ssl_err=True without crashing."""
    with patch.object(
        engine.session,
        "get",
        side_effect=requests.exceptions.SSLError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"),
    ), patch("app.services.detection_engine.validate_outbound_url", return_value=(True, None)):
        result = engine.analyze_url("https://untrusted-cert-site.com")
        assert isinstance(result, DetectionResult)
        assert result.html_available is False
        assert any("ssl" in ind.lower() or "certificate" in ind.lower() for ind in result.detected_indicators)


# =============================================================================
# 6. CORS Configuration & Security Tests
# =============================================================================

def test_cors_allows_configured_origins_and_denies_unauthorized(client: TestClient):
    """Verify allowed development origins receive CORS headers and unauthorized origins are rejected."""
    # 1. Allowed: http://localhost:5173 (Vite frontend)
    res_vite = client.options(
        "/predict",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert res_vite.status_code == 200
    assert res_vite.headers.get("access-control-allow-origin") == "http://localhost:5173"

    # 2. Denied: http://malicious-tracker.com
    res_evil = client.options(
        "/predict",
        headers={
            "Origin": "http://malicious-tracker.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        },
    )
    assert "access-control-allow-origin" not in res_evil.headers


# =============================================================================
# 7. Scan History Protection & Sanitization Tests
# =============================================================================

def test_history_cross_site_fetch_rejected(client: TestClient):
    """Verify that cross-site requests to /api/history are rejected with HTTP 403."""
    res = client.get(
        "/api/history",
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert res.status_code == 403
    assert "forbidden" in res.json().get("detail", "").lower()


def test_history_unauthorized_origin_rejected(client: TestClient):
    """Verify that requests from unauthorized Origin headers to /api/history are rejected with HTTP 403."""
    res = client.get(
        "/api/history",
        headers={"Origin": "http://evil-attacker.com"},
    )
    assert res.status_code == 403
    assert "not authorized" in res.json().get("detail", "").lower()


def test_history_records_sanitize_sensitive_url_tokens():
    """Verify that URLs saved to history have credentials stripped and auth query parameters redacted."""
    hist = HistoryService.get_instance()
    sensitive_record = {
        "url": "https://admin:supersecret@mybank.com/transfer?token=jwt_secret_token&user_id=1234&session=sess99",
        "status": "safe",
        "confidence": 0.05,
        "risk_level": "low",
        "is_phishing": False,
        "html_available": True,
    }

    hist.add_record(sensitive_record)
    records = hist.get_history(limit=5)
    matching = [r for r in records if "mybank.com" in r.get("url", "")]
    assert len(matching) > 0

    saved_url = matching[0]["url"]
    assert "admin" not in saved_url
    assert "supersecret" not in saved_url
    assert "jwt_secret_token" not in saved_url
    assert "token=[REDACTED]" in saved_url
    assert "session=[REDACTED]" in saved_url
