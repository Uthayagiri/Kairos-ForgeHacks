"""Risk Scoring and Human-Readable Indicator Generation Module.

Maps raw ML phishing probabilities into standardized risk levels (low, medium, high)
and statuses (safe, suspicious, phishing), and generates dynamic, explainable indicators
derived directly from active URL and HTML features.
"""

from typing import Any, Dict, List, Optional, Tuple

# Documented Risk Threshold Constants
LOW_RISK_THRESHOLD: float = 0.30
HIGH_RISK_THRESHOLD: float = 0.70


def has_strong_url_threat_signals(url_features: Dict[str, Any]) -> bool:
    """Evaluate whether URL features independently demonstrate high-confidence threat signals.

    Threat criteria:
      - Raw IP address used as host
      - '@' symbol obfuscation
      - Double slash redirect in path
      - Suspicious TLD AND suspicious keywords
      - Non-HTTPS connection combined with suspicious keywords, suspicious TLD, or excessive subdomains
      - URL shortening service combined with keywords or suspicious TLD

    Args:
        url_features: Dictionary of extracted URL features.

    Returns:
        True if URL independently contains strong phishing indicators.
    """
    has_ip = bool(url_features.get("has_ip_address", False))
    has_at = bool(url_features.get("has_at_symbol", False))
    has_double_slash = bool(url_features.get("has_double_slash_redirect", False))
    has_tld = bool(url_features.get("has_suspicious_tld", False))
    has_kw = bool(url_features.get("has_suspicious_keywords", False))
    uses_https = bool(url_features.get("uses_https", True))
    is_shortened = bool(url_features.get("is_shortened_url", False))
    subdomains = int(url_features.get("num_subdomains", 0))

    # Direct high-confidence flags
    if has_ip or has_at or has_double_slash:
        return True

    # Compound threat signals
    if has_tld and has_kw:
        return True

    if not uses_https and (has_kw or has_tld or subdomains >= 3 or is_shortened):
        return True

    if is_shortened and (has_kw or has_tld):
        return True

    return False


def calculate_risk_level(phishing_probability: float) -> str:
    """Map phishing probability to a standardized risk level string.

    Thresholds:
        - probability < 0.30          -> 'low'
        - 0.30 <= probability < 0.70  -> 'medium'
        - probability >= 0.70         -> 'high'

    Args:
        phishing_probability: Model predicted probability between 0.0 and 1.0.

    Returns:
        One of 'low', 'medium', 'high'.
    """
    if phishing_probability < LOW_RISK_THRESHOLD:
        return "low"
    elif phishing_probability < HIGH_RISK_THRESHOLD:
        return "medium"
    else:
        return "high"


def map_status_and_risk(
    phishing_probability: float,
    is_phishing: bool,
    html_available: bool = True,
    url_features: Optional[Dict[str, Any]] = None,
    content_rendering_incomplete: bool = False,
) -> Tuple[str, str, float]:
    """Determine the user-facing status, risk level, and adjusted confidence score.

    When HTML is unavailable (degraded mode) OR content rendering is incomplete (SPA shell):
      - If URL-only features show NO strong suspicious signals:
          Dampen confidence (bounded <= 0.48) and cap at status="suspicious", risk_level="medium".
      - If URL-only features DO show strong independent threats (raw IP, suspicious TLD + keywords, etc.):
          Preserve raw model confidence, allowing status="phishing", risk_level="high".

    Args:
        phishing_probability: Raw ML probability score (0.0 - 1.0).
        is_phishing: Binary classification decision from model.
        html_available: Whether live HTML was inspected.
        url_features: Optional extracted URL features dictionary.
        content_rendering_incomplete: Whether HTML content was fetched but is an unrendered SPA shell.

    Returns:
        Tuple of (status, risk_level, adjusted_probability).
    """
    is_degraded = (not html_available) or content_rendering_incomplete
    has_threats = has_strong_url_threat_signals(url_features or {}) if is_degraded else True

    if is_degraded:
        if not has_threats:
            # Clean URL: dampen confidence and cap at medium / suspicious
            adjusted_prob = round(min(0.48, max(0.20, phishing_probability * 0.55)), 4)
            if adjusted_prob < LOW_RISK_THRESHOLD:
                status = "safe"
                risk_level = "low"
            else:
                status = "suspicious"
                risk_level = "medium"
            return status, risk_level, adjusted_prob
        else:
            # Strong URL threat: allow high / phishing verdict
            adjusted_prob = round(phishing_probability, 4)
    else:
        adjusted_prob = round(phishing_probability, 4)

    risk_level = calculate_risk_level(adjusted_prob)
    if risk_level == "low":
        status = "safe"
    elif risk_level == "medium":
        status = "suspicious"
    else:
        status = "phishing"

    return status, risk_level, adjusted_prob


def generate_detected_indicators(
    url_features: Dict[str, Any],
    html_features: Dict[str, Any],
    html_available: bool = True,
    fetch_error: Optional[str] = None,
    ssl_error: bool = False,
    phishing_probability: float = 0.0,
    content_rendering_incomplete: bool = False,
) -> List[str]:
    """Generate a dynamic, human-readable list of detected indicators explaining the verdict.

    Evaluates specific boolean flags and numeric feature values to provide clear,
    actionable security reasoning tailored to the analyzed URL.

    Args:
        url_features: Dictionary of extracted URL features (Stage 3).
        html_features: Dictionary of extracted HTML features (Stage 4).
        html_available: Whether live HTML was successfully retrieved and parsed.
        fetch_error: Optional error description if HTML fetch was unsuccessful.
        ssl_error: Whether SSL certificate verification encountered errors.
        phishing_probability: Computed phishing probability.
        content_rendering_incomplete: Whether HTML content was fetched but is an unrendered SPA shell.

    Returns:
        List of human-readable indicator strings.
    """
    indicators: List[str] = []

    # ------------------------------------------------------------------
    # 1. URL-Based Indicators
    # ------------------------------------------------------------------
    if url_features.get("has_ip_address"):
        indicators.append("URL uses a raw IP address instead of a standard domain name.")

    if url_features.get("has_at_symbol"):
        indicators.append("URL contains an '@' symbol (often used for credential or destination obfuscation).")

    if url_features.get("has_suspicious_tld"):
        indicators.append("Domain utilizes a high-risk or commonly abused top-level domain (TLD).")

    if url_features.get("has_suspicious_keywords"):
        indicators.append("URL contains sensitive or authentication-related keywords (e.g., login, verify, account, secure).")

    if url_features.get("has_double_slash_redirect"):
        indicators.append("URL path contains '//' which can trigger open redirection.")

    if url_features.get("is_shortened_url"):
        indicators.append("Uses a known URL shortening service that conceals the true destination hostname.")

    num_subdomains = int(url_features.get("num_subdomains", 0))
    if num_subdomains >= 3:
        indicators.append(f"Excessive number of subdomains detected ({num_subdomains} subdomains).")

    if url_features.get("has_port"):
        indicators.append("URL specifies a non-standard port number.")

    if not url_features.get("uses_https", True):
        indicators.append("Connection does not use secure HTTPS encryption.")

    if url_features.get("has_url_encoding"):
        indicators.append("URL contains percent-encoded characters that may obfuscate the path structure.")

    # ------------------------------------------------------------------
    # 2. HTML-Based Indicators (when HTML is available and not an empty SPA shell)
    # ------------------------------------------------------------------
    if html_available and not html_features.get("parse_error", False):
        if html_features.get("has_login_form"):
            indicators.append("Page contains an authentication or login form requesting user credentials.")

        num_pw = int(html_features.get("num_password_fields", 0))
        if num_pw > 0 and not html_features.get("has_login_form"):
            indicators.append(f"Page contains {num_pw} password input field(s).")

        if html_features.get("has_form_action_empty_or_javascript"):
            indicators.append("Form submission action is empty or points to a javascript/anchor pseudo-handler.")

        ext_forms = int(html_features.get("num_forms_with_external_action", 0))
        if ext_forms > 0:
            indicators.append(f"Form submission sends sensitive user data to an external third-party domain ({ext_forms} form(s)).")

        if html_features.get("has_hidden_iframe"):
            indicators.append("Page embeds hidden or zero-dimension iframe element(s).")

        if html_features.get("has_suspicious_js_patterns"):
            indicators.append("Page scripts contain potentially suspicious JavaScript execution patterns.")

        num_meta_refresh = int(html_features.get("num_meta_refresh_redirects", 0))
        if num_meta_refresh > 0:
            indicators.append(f"Page utilizes meta refresh automatic redirect ({num_meta_refresh} redirect(s)).")

        mismatched_links = int(html_features.get("num_links_with_mismatched_text", 0))
        if mismatched_links > 0:
            indicators.append(f"Contains {mismatched_links} hyperlink(s) with misleading anchor text differing from destination URL.")

        ext_ratio = float(html_features.get("external_link_ratio", 0.0))
        num_links = int(html_features.get("num_links", 0))
        if ext_ratio > 0.85 and num_links >= 5:
            indicators.append(f"Unusually high proportion of external hyperlinks ({round(ext_ratio * 100)}% external).")

    # ------------------------------------------------------------------
    # 3. Environmental & Fetch Fallback Signals
    # ------------------------------------------------------------------
    if not html_available:
        reason_str = fetch_error or "site unreachable"
        has_threats = has_strong_url_threat_signals(url_features)
        if has_threats:
            indicators.append(
                f"Live HTML content could not be inspected ({reason_str}); high-risk verdict is driven by strong URL-level threat signals."
            )
        else:
            indicators.append(
                f"Live HTML content could not be inspected ({reason_str}); threat level is bounded to Suspicious/Low based on URL-only analysis."
            )
    elif content_rendering_incomplete:
        has_threats = has_strong_url_threat_signals(url_features)
        if has_threats:
            indicators.append(
                "Page appears to be a JavaScript-rendered application; static content could not be fully inspected — high-risk verdict is driven by strong URL-level threat signals."
            )
        else:
            indicators.append(
                "Page appears to be a JavaScript-rendered application; static content could not be fully inspected — verdict is bounded due to incomplete visibility into rendered content."
            )

    if ssl_error:
        indicators.append("SSL/TLS certificate verification failed or encountered security warnings.")

    # ------------------------------------------------------------------
    # 4. Safe / Baseline Indicators (if no threats detected)
    # ------------------------------------------------------------------
    is_bounded_spa = content_rendering_incomplete and not has_strong_url_threat_signals(url_features)
    if not indicators or phishing_probability < LOW_RISK_THRESHOLD or is_bounded_spa:
        positive_notes = []
        if url_features.get("uses_https"):
            positive_notes.append("Encrypted HTTPS connection.")
        positive_notes.append("Standard domain and URL structure without known obfuscation techniques.")
        if html_available and not html_features.get("has_login_form"):
            positive_notes.append("No credential harvesting forms detected on page.")

        if not indicators:
            indicators = positive_notes
        elif (phishing_probability < LOW_RISK_THRESHOLD or is_bounded_spa) and len(indicators) <= 1 and not html_available:
            indicators.extend(positive_notes)

    return indicators
