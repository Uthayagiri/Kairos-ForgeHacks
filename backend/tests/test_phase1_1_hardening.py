"""Phase 1.1 Security Verification & Hardening Regression Test Suite.

Deterministic, zero-external-network unit and integration tests verifying:
1. DNS Rebinding Immunity and Socket Connection Pinning (Sync & Async).
2. Browser Extension Origin Allowlisting (CORS boundary hardening).
3. Scan History & Telemetry Authentication (Session tokens & API key enforcement).
"""

import socket
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

from app.core.config import get_runtime_session_token, settings
from app.main import app
from app.services.detection_engine import DetectionEngine
from app.services.ssrf_guard import (
    SSRFGuardedAsyncTransport,
    SSRFGuardedNetworkBackend,
    SSRFGuardedSyncAdapter,
    is_ip_restricted,
    resolve_and_validate_all_ips,
)


@pytest.fixture(scope="module")
def client():
    """Reusable FastAPI test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def engine():
    """Fresh DetectionEngine instance with 2-second timeout."""
    return DetectionEngine(fetch_timeout=2.0)


# =============================================================================
# 1. DNS Rebinding Immunity & Connection Pinning Tests
# =============================================================================

def test_resolve_and_validate_all_ips_ipv4_and_ipv6():
    """Verify resolve_and_validate_all_ips handles IPv4, IPv6, and blocks restricted spaces."""
    # 1. Public IPv4
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
        safe, ips, err = resolve_and_validate_all_ips("example.com", 80)
        assert safe is True
        assert "93.184.216.34" in ips
        assert err is None

    # 2. Public IPv6
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1863:25c8:19e6", 80))]):
        safe, ips, err = resolve_and_validate_all_ips("ipv6.example.com", 80)
        assert safe is True
        assert "2606:2800:220:1:248:1863:25c8:19e6" in ips
        assert err is None

    # 3. Restricted IPv6: Unique Local Address (fc00::/7)
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00::1", 80))]):
        safe, ips, err = resolve_and_validate_all_ips("internal.corp", 80)
        assert safe is False
        assert "restricted" in err.lower()

    # 4. Restricted IPv6: IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", 80))]):
        safe, ips, err = resolve_and_validate_all_ips("mapped.local", 80)
        assert safe is False
        assert "restricted" in err.lower()

    # 5. Direct literal metadata IP (169.254.169.254)
    safe, ips, err = resolve_and_validate_all_ips("169.254.169.254", 80)
    assert safe is False
    assert "restricted" in err.lower()


def test_dns_rebinding_sync_connection_pinning_blocks_private_ip(engine):
    """Simulate DNS rebinding attack where pre-check resolves public IP, but socket creation resolves 127.0.0.1.

    Verify that SSRFGuardedSyncAdapter intercepts the connection attempt at socket creation
    and terminates the request before connecting to the restricted address.
    """
    call_count = 0

    def mock_rebind_getaddrinfo(host, port, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First resolution (pre-validation step) returns public IP
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        else:
            # Second resolution (socket connection step) rebinds to loopback IP
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    with patch("socket.getaddrinfo", side_effect=mock_rebind_getaddrinfo):
        ok, content, err, is_ssl = engine.fetch_single_html("http://rebind-attacker.com:8000/stolen-data")
        assert ok is False
        assert content is None
        # Must fail with connection failure / restricted destination error
        assert "connection failed" in err.lower() or "restricted" in err.lower() or "blocked" in err.lower()


@pytest.mark.anyio
async def test_dns_rebinding_async_connection_pinning_blocks_private_ip():
    """Simulate DNS rebinding attack on async fetcher where connection-time DNS resolves 169.254.169.254."""
    eng = DetectionEngine(fetch_timeout=2.0)
    call_count = 0

    def mock_rebind_getaddrinfo(host, port, *args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First resolution (pre-check) returns public IP
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]
        else:
            # Second resolution (async transport connect_tcp) rebinds to metadata IP
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

    with patch("socket.getaddrinfo", side_effect=mock_rebind_getaddrinfo):
        ok, content, err, is_ssl = await eng.fetch_single_html_async("http://rebind-aws.attacker.com/latest/meta-data")
        assert ok is False
        assert content is None
        assert "connection failed" in err.lower() or "restricted" in err.lower() or "blocked" in err.lower()


@pytest.mark.anyio
async def test_ssrf_guarded_backend_pins_socket_to_numeric_ip():
    """Verify SSRFGuardedNetworkBackend passes validated numeric IP to anyio.connect_tcp to prevent OS rebinding."""
    backend = SSRFGuardedNetworkBackend()

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]), \
         patch("anyio.connect_tcp") as mock_anyio_connect:
        # Mock anyio stream
        mock_stream = MagicMock()
        mock_stream._raw_socket.setsockopt = MagicMock()
        mock_anyio_connect.return_value = mock_stream

        await backend.connect_tcp("legitimate-example.com", 80)

        # Ensure anyio.connect_tcp was called with the literal numeric IP ("93.184.216.34"), NOT the hostname!
        mock_anyio_connect.assert_called_once()
        _, kwargs = mock_anyio_connect.call_args
        assert kwargs["remote_host"] == "93.184.216.34"
        assert kwargs["remote_port"] == 80


# =============================================================================
# 2. Extension Origin Restriction & CORS Tests
# =============================================================================

def test_cors_denies_unconfigured_extension_in_production(client: TestClient):
    """In production mode, verify unconfigured extension origins are rejected by CORS."""
    with patch.object(settings, "APP_ENV", "production"), \
         patch.object(settings, "ALLOW_DEV_EXTENSION_ORIGINS", False), \
         patch.object(settings, "ALLOWED_EXTENSION_IDS", []):

        # Preflight from unlisted extension
        res = client.options(
            "/predict",
            headers={
                "Origin": "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert "access-control-allow-origin" not in res.headers


def test_cors_allows_explicitly_configured_extension_id(client: TestClient):
    """Verify explicitly configured extension ID in ALLOWED_EXTENSION_IDS receives CORS approval."""
    prod_ext_id = "kbmfdnhgopbljmjhphkmgfmhhlgchjfl"
    with patch.object(settings, "ALLOWED_EXTENSION_IDS", [prod_ext_id]):
        res = client.options(
            "/predict",
            headers={
                "Origin": f"chrome-extension://{prod_ext_id}",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert res.headers.get("access-control-allow-origin") == f"chrome-extension://{prod_ext_id}"


def test_cors_dev_mode_permits_unpacked_32_char_chromium_id(client: TestClient):
    """In development mode, verify valid 32-letter unpacked extension origins pass, but malformed ones fail."""
    valid_dev_ext = "chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef"
    malformed_ext = "chrome-extension://malicious-extension-with-special-chars!@#"
    wildcard_ext = "chrome-extension://*"

    with patch.object(settings, "APP_ENV", "development"), \
         patch.object(settings, "ALLOW_DEV_EXTENSION_ORIGINS", True):

        # 1. Valid unpacked 32-character ID passes
        res_valid = client.options(
            "/predict",
            headers={
                "Origin": valid_dev_ext,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert res_valid.headers.get("access-control-allow-origin") == valid_dev_ext

        # 2. Malformed extension origin fails
        res_malformed = client.options(
            "/predict",
            headers={
                "Origin": malformed_ext,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert "access-control-allow-origin" not in res_malformed.headers

        # 3. Wildcard origin fails
        res_wildcard = client.options(
            "/predict",
            headers={
                "Origin": wildcard_ext,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
        assert "access-control-allow-origin" not in res_wildcard.headers


# =============================================================================
# 3. History & Telemetry Authentication Tests
# =============================================================================

def test_history_unauthenticated_request_rejected_when_auth_required(client: TestClient):
    """When REQUIRE_HISTORY_AUTH is True, requests without credentials must return HTTP 401."""
    with patch.object(settings, "REQUIRE_HISTORY_AUTH", True):
        # 1. GET /api/history
        res_hist = client.get("/api/history")
        assert res_hist.status_code == 401
        assert "credentials required" in res_hist.json().get("detail", "").lower()

        # 2. POST /api/history/clear
        res_clear = client.post("/api/history/clear")
        assert res_clear.status_code == 401

        # 3. GET /api/stats
        res_stats = client.get("/api/stats")
        assert res_stats.status_code == 401


def test_history_invalid_credentials_rejected_when_auth_required(client: TestClient):
    """When REQUIRE_HISTORY_AUTH is True, invalid credentials must return HTTP 403 Forbidden."""
    with patch.object(settings, "REQUIRE_HISTORY_AUTH", True), \
         patch.object(settings, "HISTORY_API_KEY", "prod-secret-key-999"):

        # Header with wrong key
        res = client.get(
            "/api/history",
            headers={"X-API-Key": "completely-invalid-attacker-key"},
        )
        assert res.status_code == 403
        assert "invalid" in res.json().get("detail", "").lower()


def test_history_authorized_with_configured_api_key(client: TestClient):
    """Verify request with valid configured HISTORY_API_KEY is authorized (HTTP 200)."""
    valid_key = "secure-test-admin-key-42"
    with patch.object(settings, "REQUIRE_HISTORY_AUTH", True), \
         patch.object(settings, "HISTORY_API_KEY", valid_key):

        # 1. Using X-API-Key header
        res_key = client.get(
            "/api/history?limit=5",
            headers={"X-API-Key": valid_key},
        )
        assert res_key.status_code == 200
        assert isinstance(res_key.json(), list)

        # 2. Using Authorization: Bearer header
        res_bearer = client.get(
            "/api/stats",
            headers={"Authorization": f"Bearer {valid_key}"},
        )
        assert res_bearer.status_code == 200
        assert "total_scans" in res_bearer.json()


def test_history_authorized_with_ephemeral_session_token(client: TestClient):
    """Verify request with active runtime session token is authorized (HTTP 200)."""
    # 1. Acquire ephemeral session token
    token_res = client.get("/api/auth/token")
    assert token_res.status_code == 200
    token_data = token_res.json()
    assert token_data["status"] == "authenticated"
    session_token = token_data["token"]
    assert len(session_token) >= 32

    # 2. Access /api/history using session token
    with patch.object(settings, "REQUIRE_HISTORY_AUTH", True):
        hist_res = client.get(
            "/api/history",
            headers={"X-API-Key": session_token},
        )
        assert hist_res.status_code == 200

        # 3. Access /api/stats using session token
        stats_res = client.get(
            "/api/stats",
            headers={"X-API-Key": session_token},
        )
        assert stats_res.status_code == 200

        # 4. Access /api/history/clear using session token
        clear_res = client.post(
            "/api/history/clear",
            headers={"X-API-Key": session_token},
        )
        assert clear_res.status_code == 200
        assert clear_res.json()["status"] == "cleared"


def test_history_invalid_key_rejected_even_when_require_auth_false(client: TestClient):
    """When REQUIRE_HISTORY_AUTH is False, explicitly providing a fake/invalid key must still be rejected (403)."""
    with patch.object(settings, "REQUIRE_HISTORY_AUTH", False), \
         patch.object(settings, "HISTORY_API_KEY", "real-valid-key"):

        res = client.get(
            "/api/history",
            headers={"X-API-Key": "forged-fake-key"},
        )
        assert res.status_code == 403
        assert "invalid" in res.json().get("detail", "").lower()


def test_session_token_endpoint_blocks_cross_site_and_unauthorized_origin(client: TestClient):
    """Verify /api/auth/token cannot be accessed by cross-site requests or unauthorized origins."""
    # 1. Cross-site request rejected
    res_cs = client.get(
        "/api/auth/token",
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert res_cs.status_code == 403
    assert "cross-site" in res_cs.json().get("detail", "").lower()

    # 2. Unauthorized origin rejected
    res_orig = client.get(
        "/api/auth/token",
        headers={"Origin": "http://evil-tracker.com"},
    )
    assert res_orig.status_code == 403
    assert "not authorized" in res_orig.json().get("detail", "").lower()
