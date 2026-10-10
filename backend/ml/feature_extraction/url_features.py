"""URL Feature Extraction module for Lexical and Structural Phishing Detection Signals."""

import ipaddress
import re
import urllib.parse
from typing import Dict, Union

from ml.feature_extraction.url_feature_config import (
    FEATURE_NAMES,
    SHORTENER_DOMAINS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
)

# Standard URL characters: alphanumeric and benign delimiters
STANDARD_URL_CHARS_REGEX = re.compile(r"[a-zA-Z0-9\.\-\_\/\:\?\=\&\%\#]")


def is_ip_address(host: str) -> bool:
    """Check if the given host string is a valid IPv4 or IPv6 address.

    Args:
        host: Hostname string (without port).

    Returns:
        True if host is a valid IP address, False otherwise.
    """
    if not host:
        return False
    clean_host = host.strip("[]").strip()
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def get_default_feature_dict(parse_error: bool = True) -> Dict[str, Union[int, float, bool]]:
    """Return safe default dictionary with all feature keys initialized to 0 / False."""
    defaults: Dict[str, Union[int, float, bool]] = {name: 0 for name in FEATURE_NAMES}
    for bool_key in [
        "has_at_symbol",
        "has_ip_address",
        "uses_https",
        "has_port",
        "has_url_encoding",
        "has_suspicious_tld",
        "has_suspicious_keywords",
        "has_double_slash_redirect",
        "is_shortened_url",
        "parse_error",
    ]:
        if bool_key in defaults:
            defaults[bool_key] = False

    defaults["parse_error"] = parse_error
    return defaults


def extract_url_features(url: str) -> Dict[str, Union[int, float, bool]]:
    """Extract numeric and boolean lexical/structural features from a raw URL string.

    This function is pure, deterministic, and will NEVER raise an exception on
    malformed, empty, or unexpected input strings.

    Args:
        url: Raw URL string.

    Returns:
        Dictionary mapping feature names in FEATURE_NAMES to numeric or boolean values.
    """
    if not isinstance(url, str) or not url.strip():
        return get_default_feature_dict(parse_error=True)

    url_clean = url.strip()

    try:
        # Prepend scheme if missing for accurate urllib parsing
        if not (url_clean.startswith("http://") or url_clean.startswith("https://") or "://" in url_clean):
            parse_target = f"http://{url_clean}"
            inferred_scheme = False
        else:
            parse_target = url_clean
            inferred_scheme = True

        parsed = urllib.parse.urlsplit(parse_target)

        # Root path canonicalization for HTTP/HTTPS (RFC 3986):
        # A bare trailing slash on root is equivalent to an empty path (e.g. https://google.com/ and https://google.com)
        if (parsed.scheme or "").lower() in ("http", "https") and parsed.path == "/":
            path = ""
            url_clean = urllib.parse.urlunsplit((
                parsed.scheme,
                parsed.netloc,
                "",
                parsed.query,
                parsed.fragment,
            ))
            parse_target = url_clean
            parsed = urllib.parse.urlsplit(parse_target)
        else:
            path = parsed.path or ""

        # Hostname extraction (lowercased, without port)
        hostname = (parsed.hostname or "").lower()
        netloc = (parsed.netloc or "").lower()
        query = parsed.query or ""
        url_lower = url_clean.lower()

        # 1. Length-based features
        url_length = len(url_clean)
        domain_length = len(hostname)
        path_length = len(path)

        # 2. Structural counts
        num_dots = url_clean.count(".")
        num_hyphens = url_clean.count("-")
        num_underscores = url_clean.count("_")
        num_slashes = url_clean.count("/")
        num_digits = sum(1 for c in url_clean if c.isdigit())

        # Special characters: characters outside standard alphanumeric & basic URL delimiters
        num_special_chars = sum(1 for c in url_clean if not STANDARD_URL_CHARS_REGEX.match(c))

        # Subdomain count
        if is_ip_address(hostname) or not hostname:
            num_subdomains = 0
        else:
            host_parts = [p for p in hostname.split(".") if p]
            # Standard domain has at least 2 parts (name + tld), subdomains are additional parts
            num_subdomains = max(0, len(host_parts) - 2)

        # Query parameters count
        try:
            query_params = urllib.parse.parse_qsl(query, keep_blank_values=True)
            num_query_params = len(query_params)
        except Exception:
            num_query_params = query.count("&") + 1 if query else 0

        # Path depth (number of non-empty path segments)
        path_segments = [s for s in path.split("/") if s]
        path_depth = len(path_segments)

        # 3. Binary / Flag Indicators
        has_at_symbol = "@" in url_clean
        has_ip_addr = is_ip_address(hostname)
        uses_https = parsed.scheme.lower() == "https" if inferred_scheme else url_lower.startswith("https://")

        # Explicit non-standard port in netloc
        try:
            has_port = parsed.port is not None and parsed.port not in (80, 443)
        except ValueError:
            has_port = True

        has_url_encoding = "%" in url_clean

        # Suspicious TLD check
        has_suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)

        # Suspicious keywords check
        has_suspicious_keywords = any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS)

        # Double slash redirect check (// appearing after the scheme)
        if "://" in url_clean:
            after_scheme = url_clean.split("://", 1)[1]
            has_double_slash_redirect = "//" in after_scheme
        else:
            has_double_slash_redirect = "//" in url_clean

        # Shortened URL domain check:
        # True only if the domain is a URL shortener AND the path represents a shortened redirection slug
        # (not the service's own root homepage or standard product/service navigation routes).
        is_shortener_domain = any(hostname == s or hostname.endswith(f".{s}") for s in SHORTENER_DOMAINS)
        if is_shortener_domain:
            clean_path = path.strip("/").lower()
            service_pages = {
                "", "app", "pricing", "about", "login", "signin", "signup", "register",
                "home", "features", "terms", "privacy", "contact", "help", "blog",
                "pages", "api", "support", "docs", "legal", "solutions"
            }
            if not clean_path or clean_path.split("/")[0] in service_pages:
                is_shortened_url = False
            else:
                is_shortened_url = True
        else:
            is_shortened_url = False

        features: Dict[str, Union[int, float, bool]] = {

            "url_length": url_length,
            "domain_length": domain_length,
            "path_length": path_length,
            "num_dots": num_dots,
            "num_hyphens": num_hyphens,
            "num_underscores": num_underscores,
            "num_slashes": num_slashes,
            "num_digits": num_digits,
            "num_special_chars": num_special_chars,
            "num_subdomains": num_subdomains,
            "num_query_params": num_query_params,
            "path_depth": path_depth,
            "has_at_symbol": has_at_symbol,
            "has_ip_address": has_ip_addr,
            "uses_https": uses_https,
            "has_port": has_port,
            "has_url_encoding": has_url_encoding,
            "has_suspicious_tld": has_suspicious_tld,
            "has_suspicious_keywords": has_suspicious_keywords,
            "has_double_slash_redirect": has_double_slash_redirect,
            "is_shortened_url": is_shortened_url,
            "parse_error": False,
        }

        return features

    except Exception:
        return get_default_feature_dict(parse_error=True)
