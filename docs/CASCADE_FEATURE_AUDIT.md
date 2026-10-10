# Cascade Feature Availability Audit
**Task ID**: `EXP-13-HIGH-RECALL-CASCADE-FP-REDUCTION-IMPLEMENTATION`  
**Date**: `2026-09-16`  

## 1. Feature Classification Summary
- **Total Features Audited**: 43
- **Existing & Verified**: 43
- **Existing but Unreliable**: 0
- **Missing / Requires New Extractor**: 0
- **Unsafe / Ambiguous**: 1

## 2. Invariant Rules for Stage 2 Features
> [!IMPORTANT]
> 1. **No Proof of Legitimacy from Absence**: Features such as `uses_https=1`, `num_links=0`, `has_login_form=0`, `num_password_fields=0`, `is_shortened_url=0`, or institutional TLDs must NEVER be treated by Stage 2 as proof of safety.
> 2. **Phishing Evidence Veto**: Strong phishing signals (IP hostname, suspicious redirect, obfuscated elements, hidden iframe, external form action) strictly prevent Stage 2 de-escalation.

## 3. Verified Feature Inventory Table

| Feature Name | Dtype | Source File | Used by Prod | Safe for Stage 2 | Requires HTML | May Be Unavailable | Classification |
| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :--- |
| `url_length` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `domain_length` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `path_length` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `num_dots` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `num_hyphens` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `num_underscores` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `num_slashes` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `num_digits` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `num_special_chars` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `num_subdomains` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `num_query_params` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `path_depth` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `has_at_symbol` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `has_ip_address` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `uses_https` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | No ⚠️ | No | No | **Existing and verified** |
| `has_port` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `has_url_encoding` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `has_suspicious_tld` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `has_suspicious_keywords` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `has_double_slash_redirect` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `is_shortened_url` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `url_parse_error` | `int` | `backend/ml/feature_extraction/url_features.py` | Yes | Yes | No | No | **Existing and verified** |
| `num_forms` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `num_input_fields` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `num_password_fields` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `has_login_form` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `num_forms_with_external_action` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `has_form_action_empty_or_javascript` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `num_links` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `num_internal_links` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `num_external_links` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `external_link_ratio` | `float` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `num_links_with_mismatched_text` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `num_scripts` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `num_iframes` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `has_hidden_iframe` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `has_suspicious_js_patterns` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `num_meta_refresh_redirects` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `title_length` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `has_favicon` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `num_images` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `text_to_html_ratio` | `float` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | Yes | **Existing and verified** |
| `html_parse_error` | `int` | `backend/ml/feature_extraction/html_features.py` | Yes | Yes | Yes | No | **Existing and verified** |
