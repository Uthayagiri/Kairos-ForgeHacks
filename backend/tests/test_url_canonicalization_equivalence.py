"""Regression tests for URL root path canonicalization and feature equivalence.

Verifies that:
1. Equivalent root URLs (e.g. with and without trailing slash) produce identical normalized URLs.
2. Equivalent root URLs produce identical lexical feature sets in extract_url_features.
3. Subpaths (/login), query strings, fragments, and ports remain intact.
4. SSRF defenses and security validation remain active.
5. Consistent model predictions are returned for all root variants of benign domains.
"""

import pytest
from app.services.detection_engine import DetectionEngine
from ml.feature_extraction.url_features import extract_url_features


@pytest.fixture(scope="module")
def engine():
    return DetectionEngine()


def test_root_canonicalization_in_validate_url(engine):
    """Ensure validate_url strips bare root slashes for http/https URLs."""
    ok1, norm1, err1 = engine.validate_url("https://google.com")
    ok2, norm2, err2 = engine.validate_url("https://google.com/")
    assert ok1 and ok2
    assert err1 is None and err2 is None
    assert norm1 == "https://google.com"
    assert norm2 == "https://google.com"
    assert norm1 == norm2

    ok3, norm3, err3 = engine.validate_url("https://www.google.com")
    ok4, norm4, err4 = engine.validate_url("https://www.google.com/")
    assert ok3 and ok4
    assert norm3 == "https://www.google.com"
    assert norm4 == "https://www.google.com"
    assert norm3 == norm4


def test_feature_sets_identical_for_equivalent_roots():
    """Assert extract_url_features produces identical feature dictionaries for root slash variants."""
    f_google_noslash = extract_url_features("https://google.com")
    f_google_slash = extract_url_features("https://google.com/")
    assert f_google_noslash == f_google_slash
    assert f_google_slash["path_length"] == 0
    assert f_google_slash["num_slashes"] == 2

    f_www_noslash = extract_url_features("https://www.google.com")
    f_www_slash = extract_url_features("https://www.google.com/")
    assert f_www_noslash == f_www_slash
    assert f_www_slash["path_length"] == 0
    assert f_www_slash["num_slashes"] == 2


def test_meaningful_paths_preserved(engine):
    """Assert subpaths, nested directories, and trailing slashes on subpaths are preserved."""
    ok, norm, _ = engine.validate_url("https://google.com/login")
    assert ok
    assert norm == "https://google.com/login"

    ok, norm, _ = engine.validate_url("https://google.com/login/")
    assert ok
    assert norm == "https://google.com/login/"

    ok, norm, _ = engine.validate_url("https://google.com/search/advanced")
    assert ok
    assert norm == "https://google.com/search/advanced"

    f_sub = extract_url_features("https://google.com/login")
    assert f_sub["path_length"] == len("/login")
    assert f_sub["num_slashes"] == 3


def test_query_strings_fragments_and_ports_preserved(engine):
    """Assert non-default ports, query parameters, and fragments are preserved."""
    ok, norm, _ = engine.validate_url("https://google.com:8443/")
    assert ok
    assert norm == "https://google.com:8443"
    f_port = extract_url_features(norm)
    assert f_port["has_port"] is True

    ok, norm, _ = engine.validate_url("https://google.com/?q=security&hl=en")
    assert ok
    assert "q=security" in norm
    f_query = extract_url_features(norm)
    assert f_query["num_query_params"] == 2

    ok, norm, _ = engine.validate_url("https://google.com:8080/?q=test#main")
    assert ok
    assert norm == "https://google.com:8080?q=test#main"


def test_ssrf_and_invalid_urls_still_rejected(engine):
    """Ensure security checks and invalid schemes remain fully enforced."""
    ok, _, err = engine.validate_url("javascript:alert(1)")
    assert not ok
    assert "Unsupported URL scheme" in err

    ok, _, err = engine.validate_url("data:text/html,<b>evil</b>")
    assert not ok

    ok, _, err = engine.validate_url("http://")
    assert not ok
    assert "lacks a valid hostname" in err


def test_prediction_consistency_across_google_variants(engine):
    """Assert consistent predictions across all Google URL variants in degraded mode."""
    r_google_noslash = engine.analyze_url("https://google.com", fetch_html=False)
    r_google_slash = engine.analyze_url("https://google.com/", fetch_html=False)
    r_www_noslash = engine.analyze_url("https://www.google.com", fetch_html=False)
    r_www_slash = engine.analyze_url("https://www.google.com/", fetch_html=False)

    # All Google variants must have identical safe status and low risk level
    assert r_google_noslash.status == "safe"
    assert r_google_slash.status == "safe"
    assert r_www_noslash.status == "safe"
    assert r_www_slash.status == "safe"

    assert r_google_noslash.risk_level == "low"
    assert r_google_slash.risk_level == "low"
    assert r_www_noslash.risk_level == "low"
    assert r_www_slash.risk_level == "low"

    # Equivalent pairs must be strictly equal
    assert r_google_noslash.risk_score == r_google_slash.risk_score
    assert r_google_noslash.confidence == r_google_slash.confidence
    assert r_www_noslash.risk_score == r_www_slash.risk_score
    assert r_www_noslash.confidence == r_www_slash.confidence
