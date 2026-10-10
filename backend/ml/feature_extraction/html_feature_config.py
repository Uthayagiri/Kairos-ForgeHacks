"""Configuration constants, heuristic keyword sets, and ordered feature names for HTML feature extraction."""

from typing import List, Set

# Ordered list of all features extracted from raw HTML content.
# Maintaining this exact list and order is required for consistent ML dataset assembly & model inference.
FEATURE_NAMES: List[str] = [
    # Form & input related features
    "num_forms",
    "num_input_fields",
    "num_password_fields",
    "has_login_form",
    "num_forms_with_external_action",
    "has_form_action_empty_or_javascript",
    # Link related features
    "num_links",
    "num_internal_links",
    "num_external_links",
    "external_link_ratio",
    "num_links_with_mismatched_text",
    # Script & iframe related features
    "num_scripts",
    "num_iframes",
    "has_hidden_iframe",
    "has_suspicious_js_patterns",
    "num_meta_refresh_redirects",
    # General page structure features
    "title_length",
    "has_favicon",
    "num_images",
    "text_to_html_ratio",
    # Operational parsing flag
    "parse_error",
]

# Heuristic patterns commonly found in obfuscated, dynamic redirect, or credential-harvesting JavaScript.
# Note: Heuristic and non-exhaustive; serves as statistical signal rather than static analysis engine.
SUSPICIOUS_JS_PATTERNS: List[str] = [
    "eval(",
    "document.write(",
    "unescape(",
    "string.fromcharcode(",
    "window.location",
    "location.replace(",
    "location.href",
    "atob(",
    "decodeuricomponent(",
    "\\x",
    "\\u00",
]

# Attribute / name / placeholder keywords used to detect login and authentication forms.
LOGIN_KEYWORDS: Set[str] = {
    "login",
    "signin",
    "sign-in",
    "log-in",
    "username",
    "password",
    "passwd",
    "passcode",
    "auth",
    "credential",
    "user",
    "email",
    "account",
    "pin",
    "identifier",
}

# Thresholds for detecting unrendered JavaScript Single Page Application (SPA) shells.
# When a modern React/Vue/Angular/Polymer web application is fetched without executing client-side JS,
# the raw HTML received is an empty root container with script bundles and minimal shell markup (e.g. search bar or logo).
# This heuristic distinguishes an unrendered SPA shell from a genuine static phishing page:
# - An unrendered SPA shell has very few static links (<= 20), <= 1 form, <= 3 images, and low text ratio (<= 0.05).
# - A real phishing page typically contains an active static login/credential input form.
SPA_SHELL_MAX_LINKS: int = 20
SPA_SHELL_MAX_FORMS: int = 0
SPA_SHELL_MAX_IMAGES: int = 3
SPA_SHELL_MIN_SCRIPTS: int = 1
SPA_SHELL_MAX_TEXT_RATIO: float = 0.10





