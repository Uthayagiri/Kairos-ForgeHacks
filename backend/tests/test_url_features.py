"""Unit tests for URL feature extraction logic and edge cases."""

from ml.feature_extraction.url_feature_config import FEATURE_NAMES
from ml.feature_extraction.url_features import extract_url_features, is_ip_address


def test_feature_names_completeness():
    """Ensure all extracted features match exactly with FEATURE_NAMES schema."""
    url = "https://example.com/test"
    features = extract_url_features(url)

    assert set(features.keys()) == set(FEATURE_NAMES)
    assert len(features) == len(FEATURE_NAMES)
    for name in FEATURE_NAMES:
        assert name in features


def test_clean_https_url():
    """Verify feature values for a standard benign HTTPS URL."""
    url = "https://www.example.com/products/item?id=123&ref=home"
    features = extract_url_features(url)

    assert features["uses_https"] is True
    assert features["has_ip_address"] is False
    assert features["has_at_symbol"] is False
    assert features["has_port"] is False
    assert features["has_url_encoding"] is False
    assert features["has_suspicious_tld"] is False
    assert features["num_query_params"] == 2
    assert features["path_depth"] == 2
    assert features["domain_length"] == len("www.example.com")
    assert features["num_subdomains"] == 1
    assert features["parse_error"] is False


def test_ip_address_url():
    """Verify IP address detection for IPv4 and IPv6."""
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("10.0.0.1") is True
    assert is_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
    assert is_ip_address("example.com") is False
    assert is_ip_address("192.168.1.1.com") is False

    url_ipv4 = "http://192.168.1.100:8080/login.php"
    features = extract_url_features(url_ipv4)
    assert features["has_ip_address"] is True
    assert features["has_port"] is True
    assert features["uses_https"] is False
    assert features["has_suspicious_keywords"] is True  # 'login' keyword


def test_at_symbol_obfuscation():
    """Verify detection of @ symbol in URL credentials/path."""
    url = "http://legit-brand.com@evil-phishing-host.xyz/auth/verify"
    features = extract_url_features(url)

    assert features["has_at_symbol"] is True
    assert features["has_suspicious_tld"] is True  # .xyz
    assert features["has_suspicious_keywords"] is True  # 'auth' / 'verify'


def test_excessive_subdomains():
    """Verify subdomain counting."""
    url = "https://secure.account.update.banking.portal.legitbank.com.xyz/login"
    features = extract_url_features(url)

    # host parts = ['secure', 'account', 'update', 'banking', 'portal', 'legitbank', 'com', 'xyz'] (8 parts -> 6 subdomains)
    assert features["num_subdomains"] >= 5
    assert features["has_suspicious_keywords"] is True


def test_suspicious_tld_and_keywords():
    """Verify suspicious TLD and keyword detection."""
    url = "https://paypal-security-verification.top/update/account"
    features = extract_url_features(url)

    assert features["has_suspicious_tld"] is True
    assert features["has_suspicious_keywords"] is True
    assert features["num_hyphens"] == 2


def test_url_encoding_and_double_slash():
    """Verify URL encoding and double slash redirect detection."""
    url = "http://attacker.com/redirect?url=http://victim.com%20login"
    features = extract_url_features(url)

    assert features["has_url_encoding"] is True
    assert features["has_double_slash_redirect"] is True


def test_shortened_url():
    """Verify URL shortener recognition."""
    url = "https://bit.ly/secure-login-3902"
    features = extract_url_features(url)

    assert features["is_shortened_url"] is True


def test_malformed_and_garbage_string():
    """Verify malformed input does not throw exceptions and returns safe defaults."""
    garbage = ":::not a valid url;;; %%% @@@"
    features = extract_url_features(garbage)

    assert isinstance(features, dict)
    assert set(features.keys()) == set(FEATURE_NAMES)
    assert features["url_length"] == len(garbage)


def test_empty_and_none_input():
    """Verify empty/None strings return safe default feature dicts with parse_error True."""
    features_empty = extract_url_features("")
    assert features_empty["parse_error"] is True
    assert features_empty["url_length"] == 0
    assert features_empty["uses_https"] is False

    features_spaces = extract_url_features("    ")
    assert features_spaces["parse_error"] is True

    features_none = extract_url_features(None)
    assert features_none["parse_error"] is True
