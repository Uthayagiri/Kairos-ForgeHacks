import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from bs4 import BeautifulSoup
import numpy as np
import pandas as pd

HTML_CACHE_DIR = Path("backend/data/raw/html_cache")
DATA_DIR = Path("backend/data/processed")

# Known targeted brand keywords
TARGET_BRANDS = {
    "microsoft", "office365", "outlook", "live", "onedrive", "sharepoint",
    "google", "gmail", "drive", "docs", "workspace",
    "apple", "icloud", "itunes", "appleid",
    "paypal", "netflix", "amazon", "aws", "facebook", "meta", "instagram",
    "whatsapp", "telegram", "chase", "wellsfargo", "bankofamerica", "citi",
    "barclays", "hsbc", "dhl", "fedex", "usps", "ups", "coinbase", "binance",
    "metamask", "kraken", "blockchain", "steam", "adobe", "dropbox", "docuSign",
    "yahoo", "aol", "att", "verizon", "xfinity", "tmobile"
}

LOGIN_KEYWORDS_SET = {
    "login", "signin", "sign-in", "log-in", "username", "password", "passwd",
    "passcode", "auth", "authenticate", "credential", "user", "email", "account",
    "verify", "verification", "secure", "security", "update", "billing", "invoice"
}

HIDDEN_STYLE_REGEX = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(\.0+)?|width\s*:\s*0(px)?|height\s*:\s*0(px)?)",
    re.IGNORECASE,
)

def extract_registered_domain(url_str: str) -> str:
    try:
        if not isinstance(url_str, str) or not url_str.strip():
            return "unknown"
        target = url_str if "://" in url_str else f"http://{url_str}"
        host = urllib.parse.urlsplit(target).hostname or "unknown"
        host = host.lower().strip(".")
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return "unknown"

def extract_semantic_features(url: str, html_content: str) -> dict:
    page_domain = extract_registered_domain(url)
    target = url if "://" in url else f"http://{url}"
    try:
        parsed_url = urllib.parse.urlsplit(target)
        hostname = (parsed_url.hostname or "").lower().strip(".")
    except Exception:
        hostname = ""

    if not html_content or not isinstance(html_content, str) or len(html_content.strip()) == 0:
        return {
            # Group B: Form behavior
            "has_external_form_action": 0,
            "form_action_domain_mismatch": 0,
            "password_field_present": 0,
            "credential_collection_pattern": 0,
            "form_without_action_or_post": 0,
            # Group C: Page structure
            "hidden_element_count": 0,
            "inline_script_ratio": 0.0,
            "external_script_ratio": 0.0,
            "external_script_domain_count": 0,
            "meta_refresh_present": 0,
            "has_data_or_blob_script": 0,
            # Group D: URL/Content consistency
            "title_word_count": 0,
            "suspicious_keyword_density": 0.0,
            "login_keyword_density": 0.0,
            "url_brand_in_title_mismatch": 0,
            "domain_in_title_present": 0,
        }

    try:
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception:
        return {
            "has_external_form_action": 0,
            "form_action_domain_mismatch": 0,
            "password_field_present": 0,
            "credential_collection_pattern": 0,
            "form_without_action_or_post": 0,
            "hidden_element_count": 0,
            "inline_script_ratio": 0.0,
            "external_script_ratio": 0.0,
            "external_script_domain_count": 0,
            "meta_refresh_present": 0,
            "has_data_or_blob_script": 0,
            "title_word_count": 0,
            "suspicious_keyword_density": 0.0,
            "login_keyword_density": 0.0,
            "url_brand_in_title_mismatch": 0,
            "domain_in_title_present": 0,
        }

    # 1. Form Behavior
    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    pw_inputs = [inp for inp in inputs if (inp.get("type") or "").lower() == "password"]
    password_field_present = 1 if len(pw_inputs) > 0 else 0

    has_external_form_action = 0
    form_action_domain_mismatch = 0
    form_without_action_or_post = 0
    credential_collection_pattern = 0

    for f in forms:
        action = (f.get("action") or "").strip()
        action_lower = action.lower()
        method = (f.get("method") or "get").lower().strip()

        if not action or action_lower in ("#", "about:blank", "") or action_lower.startswith("javascript:"):
            form_without_action_or_post = 1

        if action and "://" in action:
            try:
                action_host = (urllib.parse.urlsplit(action).hostname or "").lower()
                action_apex = extract_registered_domain(action)
                if action_apex and action_apex != page_domain:
                    has_external_form_action = 1
                    form_action_domain_mismatch = 1
            except Exception:
                pass

        # Credential pattern: form with password or login keyword submitting externally or having missing action
        form_text = " ".join([str(f.get("name") or ""), str(f.get("id") or ""), str(f.get("action") or "")]).lower()
        has_login_kw = any(k in form_text for k in ["login", "signin", "auth", "credential", "account"])
        form_pws = f.find_all("input", type=lambda t: t and t.lower() == "password")
        if (len(form_pws) > 0 or has_login_kw) and (has_external_form_action or form_without_action_or_post):
            credential_collection_pattern = 1

    # 2. Page Structure & Scripts
    hidden_inputs = len(soup.find_all("input", type="hidden"))
    elements_with_style = soup.find_all(attrs={"style": True})
    hidden_styles = sum(1 for el in elements_with_style if HIDDEN_STYLE_REGEX.search(el.get("style", "")))
    hidden_element_count = min(100, hidden_inputs + hidden_styles)

    scripts = soup.find_all("script")
    num_scripts = len(scripts)
    inline_scripts = 0
    external_scripts = 0
    external_script_domains = set()
    has_data_or_blob_script = 0

    for s in scripts:
        src = (s.get("src") or "").strip()
        if not src:
            inline_scripts += 1
        else:
            external_scripts += 1
            if src.lower().startswith(("data:", "blob:")):
                has_data_or_blob_script = 1
            if "://" in src:
                try:
                    s_host = extract_registered_domain(src)
                    if s_host and s_host != page_domain:
                        external_script_domains.add(s_host)
                except Exception:
                    pass

    inline_script_ratio = round(inline_scripts / num_scripts, 4) if num_scripts > 0 else 0.0
    external_script_ratio = round(external_scripts / num_scripts, 4) if num_scripts > 0 else 0.0
    external_script_domain_count = min(50, len(external_script_domains))

    meta_refresh_tags = soup.find_all("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"})
    meta_refresh_present = 1 if len(meta_refresh_tags) > 0 else 0

    # 3. URL/Content Consistency & Brand Impersonation
    title_tag = soup.find("title")
    title_text = title_tag.get_text(separator=" ", strip=True).lower() if title_tag else ""
    title_words = title_text.split()
    title_word_count = min(50, len(title_words))

    visible_text = soup.get_text(separator=" ", strip=True).lower()
    text_words = visible_text.split()
    total_words = len(text_words)

    if total_words > 0:
        kw_hits = sum(1 for w in text_words if w in LOGIN_KEYWORDS_SET)
        suspicious_keyword_density = min(1.0, round(float(kw_hits / max(10, total_words)), 4))
        login_kw_hits = sum(1 for w in text_words if w in ("login", "signin", "password", "credential", "auth"))
        login_keyword_density = min(1.0, round(float(login_kw_hits / max(10, total_words)), 4))
    else:
        suspicious_keyword_density = 0.0
        login_keyword_density = 0.0

    # Brand in Title vs URL Apex Mismatch
    # e.g., Title has "PayPal" or "Microsoft" but apex domain is NOT paypal.com or microsoft.com
    url_brand_in_title_mismatch = 0
    domain_in_title_present = 0

    # Check if any brand is in title
    for brand in TARGET_BRANDS:
        if brand in title_text or f"sign in to {brand}" in visible_text or f"{brand} login" in visible_text:
            # Check if brand is in the apex domain
            if brand not in page_domain:
                url_brand_in_title_mismatch = 1
                break

    apex_token = page_domain.split(".")[0] if page_domain and "." in page_domain else page_domain
    if apex_token and len(apex_token) >= 3 and apex_token in title_text:
        domain_in_title_present = 1

    return {
        # Group B: Form Behavior
        "has_external_form_action": has_external_form_action,
        "form_action_domain_mismatch": form_action_domain_mismatch,
        "password_field_present": password_field_present,
        "credential_collection_pattern": credential_collection_pattern,
        "form_without_action_or_post": form_without_action_or_post,
        # Group C: Page Structure
        "hidden_element_count": hidden_element_count,
        "inline_script_ratio": inline_script_ratio,
        "external_script_ratio": external_script_ratio,
        "external_script_domain_count": external_script_domain_count,
        "meta_refresh_present": meta_refresh_present,
        "has_data_or_blob_script": has_data_or_blob_script,
        # Group D: URL/Content Consistency
        "title_word_count": title_word_count,
        "suspicious_keyword_density": suspicious_keyword_density,
        "login_keyword_density": login_keyword_density,
        "url_brand_in_title_mismatch": url_brand_in_title_mismatch,
        "domain_in_title_present": domain_in_title_present,
    }

# Test on 100 samples
df_exp = pd.read_csv(DATA_DIR / "training_dataset_expanded.csv")
sample_records = []
for idx, row in df_exp.head(200).iterrows():
    u = row["url"]
    h = hashlib.sha256(u.strip().encode("utf-8")).hexdigest()
    f = HTML_CACHE_DIR / f"{h}.html"
    content = f.read_text(encoding="utf-8", errors="replace") if f.exists() else ""
    feats = extract_semantic_features(u, content)
    feats["label"] = row["label"]
    sample_records.append(feats)

df_sample = pd.DataFrame(sample_records)
print("Sample extracted successfully! Shape:", df_sample.shape)
print("\nFeature means by class:")
print(df_sample.groupby("label").mean().T)
