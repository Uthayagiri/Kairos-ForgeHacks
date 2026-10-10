"""Unit tests for HTML fetching functions with mocked network requests."""

from unittest.mock import MagicMock, patch

import requests

from ml.data_collection.fetch_html import fetch_html_for_url, get_url_hash


def test_get_url_hash():
    """Verify SHA-256 hash generation is deterministic."""
    url = "https://example.com/test-path"
    h1 = get_url_hash(url)
    h2 = get_url_hash(url)
    assert h1 == h2
    assert len(h1) == 64


@patch("requests.get")
def test_fetch_html_success(mock_get, tmp_path):
    """Verify successful 200 OK HTML fetch."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
    mock_resp.encoding = "utf-8"
    mock_resp.iter_content.return_value = [b"<html><head><title>Sample</title></head><body>Content</body></html>"]
    mock_get.return_value = mock_resp

    test_url = "https://unit-test-domain-legit-example-123.org"
    result = fetch_html_for_url(
        url=test_url,
        label="legitimate",
        source="Tranco",
        save_cache=False,
    )

    assert result["fetch_success"] is True
    assert result["http_status"] == 200
    assert result["url"] == test_url
    assert result["label"] == "legitimate"
    assert result["error_reason"] == ""


@patch("requests.get")
def test_fetch_html_timeout(mock_get):
    """Verify graceful handling when request times out."""
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")

    test_url = "https://unit-test-timeout-example-456.org"
    result = fetch_html_for_url(
        url=test_url,
        label="phishing",
        source="PhishTank",
        save_cache=False,
    )

    assert result["fetch_success"] is False
    assert result["http_status"] is None
    assert result["url"] == test_url
    assert "timeout" in result["error_reason"].lower()


@patch("requests.get")
def test_fetch_html_non_200_status(mock_get):
    """Verify non-200 HTTP responses (e.g. 404, 500) are recorded gracefully."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_get.return_value = mock_resp

    test_url = "https://unit-test-404-example-789.org"
    result = fetch_html_for_url(
        url=test_url,
        label="legitimate",
        source="Tranco",
        save_cache=False,
    )

    assert result["fetch_success"] is False
    assert result["http_status"] == 404
    assert result["html_file_path"] == ""
    assert "404" in result["error_reason"]


@patch("requests.get")
def test_fetch_html_non_html_content_type(mock_get):
    """Verify non-HTML content (e.g. application/pdf) is rejected."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "application/pdf"}
    mock_get.return_value = mock_resp

    test_url = "https://unit-test-pdf-example-999.org/sample.pdf"
    result = fetch_html_for_url(
        url=test_url,
        label="legitimate",
        source="Tranco",
        save_cache=False,
    )

    assert result["fetch_success"] is False
    assert result["http_status"] == 200
    assert "Non-HTML" in result["error_reason"]


@patch("requests.get")
def test_fetch_html_ssl_error(mock_get):
    """Verify SSL exceptions are caught and handled gracefully."""
    mock_get.side_effect = requests.exceptions.SSLError("Certificate verify failed")

    test_url = "https://unit-test-ssl-fail-example.org"
    result = fetch_html_for_url(
        url=test_url,
        label="phishing",
        source="OpenPhish",
        save_cache=False,
    )

    assert result["fetch_success"] is False
    assert result["http_status"] is None
    assert "SSL" in result["error_reason"]
