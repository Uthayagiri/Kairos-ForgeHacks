"""HTML Feature Extraction module for Form, Link, Script, and Structural Phishing Signals."""

import re
import urllib.parse
import warnings
from typing import Dict, Union

from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

# Suppress XMLParsedAsHTMLWarning when BeautifulSoup parses XHTML/XML documents as HTML
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


from ml.feature_extraction.html_feature_config import (
    FEATURE_NAMES,
    LOGIN_KEYWORDS,
    SPA_SHELL_MAX_FORMS,
    SPA_SHELL_MAX_IMAGES,
    SPA_SHELL_MAX_LINKS,
    SPA_SHELL_MAX_TEXT_RATIO,
    SPA_SHELL_MIN_SCRIPTS,
    SUSPICIOUS_JS_PATTERNS,
)

# Regex to detect hidden CSS properties in style attributes
HIDDEN_STYLE_REGEX = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(\.0+)?|width\s*:\s*0(px)?|height\s*:\s*0(px)?)",
    re.IGNORECASE,
)

# Regex to detect visible text that looks like a domain or URL
URL_LIKE_TEXT_REGEX = re.compile(
    r"(https?://|www\.)[a-zA-Z0-9\.\-]+|[a-zA-Z0-9\-]+\.(com|net|org|edu|gov|io|co|xyz|top|info|biz|uk|de|ru|cn|jp)",
    re.IGNORECASE,
)


# Regex to detect actual HTML tag structures
HTML_TAG_REGEX = re.compile(r"<[a-zA-Z\/!][^>]*>")


def is_likely_unrendered_spa_shell(html_features: Dict[str, Union[int, float, bool]]) -> bool:
    """Evaluate whether extracted HTML features indicate an unrendered client-side Single Page Application shell.

    Client-side frameworks (React, Vue, Angular, Svelte, Polymer) deliver an initial HTML shell containing
    script bundles and an empty root container with minimal header chrome. When parsed statically,
    such pages appear to have very few links and low text content.

    Criteria:
      - num_links <= SPA_SHELL_MAX_LINKS (<= 20)
      - num_forms <= SPA_SHELL_MAX_FORMS (<= 1)
      - num_images <= SPA_SHELL_MAX_IMAGES (<= 3)
      - num_scripts >= SPA_SHELL_MIN_SCRIPTS (>= 2)
      - text_to_html_ratio <= SPA_SHELL_MAX_TEXT_RATIO (<= 0.05)
      - has_login_form is False (critical security guard: credential forms are never benign SPA shells)
      - parse_error is False (i.e. HTML was successfully parsed, not an empty or broken fetch)

    Args:
        html_features: Dictionary of extracted HTML features.

    Returns:
        True if the HTML features match the signature of an unrendered SPA shell.
    """
    if not html_features or html_features.get("parse_error", False):
        return False

    num_links = int(html_features.get("num_links", 0))
    num_forms = int(html_features.get("num_forms", 0))
    num_images = int(html_features.get("num_images", 0))
    num_scripts = int(html_features.get("num_scripts", 0))
    text_ratio = float(html_features.get("text_to_html_ratio", 0.0))
    has_login_form = bool(html_features.get("has_login_form", False))

    if has_login_form:
        return False

    return (
        num_links <= SPA_SHELL_MAX_LINKS
        and num_forms <= SPA_SHELL_MAX_FORMS
        and num_images <= SPA_SHELL_MAX_IMAGES
        and num_scripts >= SPA_SHELL_MIN_SCRIPTS
        and text_ratio <= SPA_SHELL_MAX_TEXT_RATIO
    )



def get_default_html_feature_dict(parse_error: bool = True) -> Dict[str, Union[int, float, bool]]:
    """Return default dictionary with all HTML features initialized to 0, 0.0, or False."""
    defaults: Dict[str, Union[int, float, bool]] = {name: 0 for name in FEATURE_NAMES}
    for float_key in ["external_link_ratio", "text_to_html_ratio"]:
        if float_key in defaults:
            defaults[float_key] = 0.0

    for bool_key in [
        "has_login_form",
        "has_form_action_empty_or_javascript",
        "has_hidden_iframe",
        "has_suspicious_js_patterns",
        "has_favicon",
        "parse_error",
    ]:
        if bool_key in defaults:
            defaults[bool_key] = False

    defaults["parse_error"] = parse_error
    return defaults


def extract_html_features(
    html_content: str,
    page_url: str = "",
) -> Dict[str, Union[int, float, bool]]:
    """Extract structured numeric and boolean features from raw HTML content.

    This function is completely offline (no network calls) and never raises exceptions.

    Args:
        html_content: Raw HTML content string.
        page_url: Optional URL of the page for link origin and external-form comparison.

    Returns:
        Dictionary mapping all keys in html_feature_config.FEATURE_NAMES to extracted values.
    """
    if not isinstance(html_content, str) or not html_content.strip():
        return get_default_html_feature_dict(parse_error=True)

    # Reject binary data (e.g. null bytes) or non-HTML strings without tags
    if "\x00" in html_content or not HTML_TAG_REGEX.search(html_content):
        return get_default_html_feature_dict(parse_error=True)


    # Extract base domain from page_url for internal vs external comparison
    page_domain = ""
    if page_url and isinstance(page_url, str):
        try:
            url_target = page_url if "://" in page_url else f"http://{page_url}"
            page_domain = (urllib.parse.urlsplit(url_target).hostname or "").lower()
        except Exception:
            page_domain = ""

    # Parse HTML with BeautifulSoup (preferring fast lxml, fallback to html.parser)
    soup = None
    try:
        soup = BeautifulSoup(html_content, "lxml")
    except Exception:
        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception:
            return get_default_html_feature_dict(parse_error=True)

    if soup is None or not soup.find():
        # Check if content has at least some basic HTML-like structure
        if "<" not in html_content or ">" not in html_content:
            return get_default_html_feature_dict(parse_error=True)

    try:
        # -------------------------------------------------------------
        # 1. Form & Input Features
        # -------------------------------------------------------------
        forms = soup.find_all("form")
        num_forms = len(forms)

        all_inputs = soup.find_all("input")
        num_input_fields = len(all_inputs)

        password_inputs = [inp for inp in all_inputs if (inp.get("type") or "").lower() == "password"]
        num_password_fields = len(password_inputs)

        # Login form heuristic
        has_login_form = num_password_fields > 0
        if not has_login_form and forms:
            for form in forms:
                form_text_attrs = " ".join(
                    [
                        str(form.get("name") or ""),
                        str(form.get("id") or ""),
                        str(form.get("action") or ""),
                        " ".join(form.get("class") or []),
                    ]
                ).lower()
                if any(kw in form_text_attrs for kw in ["login", "signin", "auth", "credential"]):
                    has_login_form = True
                    break

                # Inspect form child inputs
                for inp in form.find_all(["input", "button"]):
                    inp_attrs = " ".join(
                        [
                            str(inp.get("name") or ""),
                            str(inp.get("id") or ""),
                            str(inp.get("placeholder") or ""),
                            str(inp.get("type") or ""),
                        ]
                    ).lower()
                    if any(kw in inp_attrs for kw in LOGIN_KEYWORDS):
                        has_login_form = True
                        break
                if has_login_form:
                    break

        num_forms_with_external_action = 0
        has_form_action_empty_or_javascript = False

        for form in forms:
            action = (form.get("action") or "").strip()
            action_lower = action.lower()

            if not action or action_lower in ("", "#", "about:blank") or action_lower.startswith("javascript:"):
                has_form_action_empty_or_javascript = True

            if action and page_domain and "://" in action:
                try:
                    action_host = (urllib.parse.urlsplit(action).hostname or "").lower()
                    if action_host and action_host != page_domain and not action_host.endswith(f".{page_domain}"):
                        num_forms_with_external_action += 1
                except Exception:
                    pass

        # -------------------------------------------------------------
        # 2. Link Features
        # -------------------------------------------------------------
        a_tags = soup.find_all("a", href=True)
        num_links = len(a_tags)
        num_internal_links = 0
        num_external_links = 0
        num_links_with_mismatched_text = 0

        for a in a_tags:
            href = (a.get("href") or "").strip()
            href_lower = href.lower()

            is_external = False
            link_host = ""

            if href_lower.startswith("http://") or href_lower.startswith("https://") or href_lower.startswith("//"):
                try:
                    parse_target = href if not href.startswith("//") else f"http:{href}"
                    link_host = (urllib.parse.urlsplit(parse_target).hostname or "").lower()
                    if page_domain and link_host and link_host != page_domain and not link_host.endswith(f".{page_domain}"):
                        is_external = True
                except Exception:
                    pass

            if is_external:
                num_external_links += 1
            else:
                num_internal_links += 1

            # Mismatched anchor text heuristic
            anchor_text = a.get_text(strip=True)
            if anchor_text and URL_LIKE_TEXT_REGEX.search(anchor_text):
                try:
                    text_match = URL_LIKE_TEXT_REGEX.search(anchor_text).group(0)
                    text_target = text_match if "://" in text_match else f"http://{text_match}"
                    text_host = (urllib.parse.urlsplit(text_target).hostname or "").lower()
                    if text_host and link_host and text_host != link_host and not link_host.endswith(f".{text_host}"):
                        num_links_with_mismatched_text += 1
                except Exception:
                    pass

        external_link_ratio = round(num_external_links / num_links, 4) if num_links > 0 else 0.0

        # -------------------------------------------------------------
        # 3. Script & Iframe Features
        # -------------------------------------------------------------
        scripts = soup.find_all("script")
        num_scripts = len(scripts)

        iframes = soup.find_all("iframe")
        num_iframes = len(iframes)
        has_hidden_iframe = False

        for iframe in iframes:
            width = str(iframe.get("width") or "").strip()
            height = str(iframe.get("height") or "").strip()
            style = str(iframe.get("style") or "")

            if (
                width in ("0", "0px")
                or height in ("0", "0px")
                or iframe.has_attr("hidden")
                or HIDDEN_STYLE_REGEX.search(style)
            ):
                has_hidden_iframe = True
                break

        # Suspicious JS patterns heuristic
        has_suspicious_js_patterns = False
        all_scripts_text = " ".join([script.get_text() for script in scripts]).lower()
        if any(pat in all_scripts_text for pat in SUSPICIOUS_JS_PATTERNS):
            has_suspicious_js_patterns = True

        # Meta refresh tag redirects
        meta_tags = soup.find_all("meta")
        num_meta_refresh_redirects = 0
        for meta in meta_tags:
            http_equiv = str(meta.get("http-equiv") or "").strip().lower()
            if http_equiv == "refresh":
                num_meta_refresh_redirects += 1

        # -------------------------------------------------------------
        # 4. General Page Structure Features
        # -------------------------------------------------------------
        title_tag = soup.find("title")
        title_length = len(title_tag.get_text(strip=True)) if title_tag else 0

        favicon_links = soup.find_all("link", rel=lambda r: r and any("icon" in str(x).lower() for x in (r if isinstance(r, list) else [r])))
        has_favicon = len(favicon_links) > 0

        images = soup.find_all("img")
        num_images = len(images)

        # Text-to-HTML ratio
        total_html_len = len(html_content)
        visible_text = soup.get_text(separator=" ", strip=True)
        text_to_html_ratio = round(len(visible_text) / total_html_len, 4) if total_html_len > 0 else 0.0

        return {
            "num_forms": num_forms,
            "num_input_fields": num_input_fields,
            "num_password_fields": num_password_fields,
            "has_login_form": has_login_form,
            "num_forms_with_external_action": num_forms_with_external_action,
            "has_form_action_empty_or_javascript": has_form_action_empty_or_javascript,
            "num_links": num_links,
            "num_internal_links": num_internal_links,
            "num_external_links": num_external_links,
            "external_link_ratio": external_link_ratio,
            "num_links_with_mismatched_text": num_links_with_mismatched_text,
            "num_scripts": num_scripts,
            "num_iframes": num_iframes,
            "has_hidden_iframe": has_hidden_iframe,
            "has_suspicious_js_patterns": has_suspicious_js_patterns,
            "num_meta_refresh_redirects": num_meta_refresh_redirects,
            "title_length": title_length,
            "has_favicon": has_favicon,
            "num_images": num_images,
            "text_to_html_ratio": text_to_html_ratio,
            "parse_error": False,
        }

    except Exception:
        return get_default_html_feature_dict(parse_error=True)
