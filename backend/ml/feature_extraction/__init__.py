from ml.feature_extraction.html_feature_config import (
    FEATURE_NAMES as HTML_FEATURE_NAMES,
    LOGIN_KEYWORDS,
    SPA_SHELL_MAX_FORMS,
    SPA_SHELL_MAX_IMAGES,
    SPA_SHELL_MAX_LINKS,
    SPA_SHELL_MAX_TEXT_RATIO,
    SPA_SHELL_MIN_SCRIPTS,
    SUSPICIOUS_JS_PATTERNS,
)
from ml.feature_extraction.html_features import extract_html_features, is_likely_unrendered_spa_shell
from ml.feature_extraction.url_feature_config import (
    FEATURE_NAMES as URL_FEATURE_NAMES,
    SHORTENER_DOMAINS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
)
from ml.feature_extraction.url_features import extract_url_features, is_ip_address

__all__ = [
    "extract_url_features",
    "extract_html_features",
    "is_likely_unrendered_spa_shell",
    "is_ip_address",
    "URL_FEATURE_NAMES",
    "HTML_FEATURE_NAMES",
    "SUSPICIOUS_TLDS",
    "SUSPICIOUS_KEYWORDS",
    "SHORTENER_DOMAINS",
    "SUSPICIOUS_JS_PATTERNS",
    "LOGIN_KEYWORDS",
    "SPA_SHELL_MAX_LINKS",
    "SPA_SHELL_MAX_FORMS",
    "SPA_SHELL_MAX_IMAGES",
    "SPA_SHELL_MIN_SCRIPTS",
    "SPA_SHELL_MAX_TEXT_RATIO",
]
