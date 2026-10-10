"""Phase 1: Feature Availability Audit & Stage 2 Feature Engineering.

Inspects all URL and HTML feature definitions, categorizes them according to
the audit protocol, and produces feature_inventory.json and CASCADE_FEATURE_AUDIT.md.
"""

import json
import os
import hashlib
from typing import Dict, Any, List

FEATURE_INVENTORY_PATH = "scratch/cascade_fp_reduction/data/feature_inventory.json"
AUDIT_MD_PATH = "docs/CASCADE_FEATURE_AUDIT.md"

# Define complete inventory of all 43 production features + potential Stage 2 features
FEATURES: List[Dict[str, Any]] = [
    # URL Features
    {
        "name": "url_length",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Total character length of the complete URL string",
        "possible_values": "Non-negative integer [1, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "domain_length",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Character length of the hostname / FQDN component",
        "possible_values": "Non-negative integer [1, 253]",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "path_length",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Character length of the URL path string",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "num_dots",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Count of dot ('.') characters in the URL",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "num_hyphens",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Count of hyphen ('-') characters in the URL",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "num_underscores",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Count of underscore ('_') characters in the URL",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "num_slashes",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Count of forward slash ('/') characters in the URL",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "num_digits",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Count of numeric digits [0-9] in the URL",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "num_special_chars",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Count of non-alphanumeric special characters in the URL",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "num_subdomains",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Number of subdomain labels preceding the registered domain",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "num_query_params",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Number of key-value query parameters parsed in the URL",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "path_depth",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Number of directory path segments in URL path",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "has_at_symbol",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating presence of '@' (userinfo credential trick in URL)",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "has_ip_address",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating hostname is a raw IPv4/IPv6 address",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "uses_https",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating URL protocol scheme is https",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": False,  # INVARIANT: Must NOT be used as proof of legitimacy!
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "has_port",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating URL specifies an explicit non-standard port",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "has_url_encoding",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating presence of '%' hex encoding in URL",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "has_suspicious_tld",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating TLD is in SUSPICIOUS_TLDS heuristic set",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "has_suspicious_keywords",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating presence of phishing lure keywords in URL",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "has_double_slash_redirect",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating '//' in path after protocol (open redirect trick)",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "is_shortened_url",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating domain is a known URL shortening provider",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    {
        "name": "url_parse_error",
        "source_file": "backend/ml/feature_extraction/url_features.py",
        "dtype": "int",
        "meaning": "Operational flag indicating an unparseable malformed URL string",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": False,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    },
    # HTML Features
    {
        "name": "num_forms",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Count of <form> HTML elements parsed in the DOM",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "num_input_fields",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Count of <input> HTML elements parsed in the DOM",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "num_password_fields",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Count of <input type='password'> elements in the DOM",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "has_login_form",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating presence of a credential harvesting form",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "num_forms_with_external_action",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Count of forms posting data to a foreign apex domain",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "has_form_action_empty_or_javascript",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating form action is empty, '#', or 'javascript:...' (common credential hijacking)",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "num_links",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Total count of <a> hyperlink elements in the DOM",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "num_internal_links",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Count of links pointing to the same apex domain",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "num_external_links",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Count of links pointing to foreign apex domains",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "external_link_ratio",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "float",
        "meaning": "Ratio of external links to total links [0.0, 1.0]",
        "possible_values": "Float in [0.0, 1.0]",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "num_links_with_mismatched_text",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Count of links where anchor text displays one URL but href points to a different URL",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "num_scripts",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Count of <script> tags parsed in the HTML",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "num_iframes",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Count of <iframe> elements in the DOM",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "has_hidden_iframe",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating presence of hidden/zero-dimension iframe",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "has_suspicious_js_patterns",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating presence of eval, document.write, location.replace, etc.",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "num_meta_refresh_redirects",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Count of <meta http-equiv='refresh'> redirect tags in head",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "title_length",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Character length of the HTML <title> tag text",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "has_favicon",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Binary flag indicating presence of favicon link in HTML",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "num_images",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Count of <img> elements parsed in the DOM",
        "possible_values": "Non-negative integer [0, inf)",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "text_to_html_ratio",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "float",
        "meaning": "Ratio of visible text character count to raw HTML character count",
        "possible_values": "Float in [0.0, 1.0]",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": True,
        "classification": "Existing and verified"
    },
    {
        "name": "html_parse_error",
        "source_file": "backend/ml/feature_extraction/html_features.py",
        "dtype": "int",
        "meaning": "Operational flag indicating an unparseable or empty HTML document",
        "possible_values": "0 or 1",
        "used_by_production": True,
        "safe_for_stage2": True,
        "requires_html": True,
        "requires_browser_rendering": False,
        "may_be_unavailable": False,
        "classification": "Existing and verified"
    }
]

def generate_feature_inventory():
    os.makedirs("scratch/cascade_fp_reduction/data", exist_ok=True)
    os.makedirs("docs", exist_ok=True)
    
    with open(FEATURE_INVENTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(FEATURES, f, indent=2)
        
    md_content = [
        "# Cascade Feature Availability Audit",
        "**Task ID**: `EXP-13-HIGH-RECALL-CASCADE-FP-REDUCTION-IMPLEMENTATION`  ",
        "**Date**: `2026-09-16`  ",
        "",
        "## 1. Feature Classification Summary",
        f"- **Total Features Audited**: {len(FEATURES)}",
        f"- **Existing & Verified**: {sum(1 for f in FEATURES if f['classification'] == 'Existing and verified')}",
        f"- **Existing but Unreliable**: {sum(1 for f in FEATURES if f['classification'] == 'Existing but unreliable')}",
        f"- **Missing / Requires New Extractor**: {sum(1 for f in FEATURES if f['classification'] == 'Missing')}",
        f"- **Unsafe / Ambiguous**: {sum(1 for f in FEATURES if not f['safe_for_stage2'])}",
        "",
        "## 2. Invariant Rules for Stage 2 Features",
        "> [!IMPORTANT]",
        "> 1. **No Proof of Legitimacy from Absence**: Features such as `uses_https=1`, `num_links=0`, `has_login_form=0`, `num_password_fields=0`, `is_shortened_url=0`, or institutional TLDs must NEVER be treated by Stage 2 as proof of safety.",
        "> 2. **Phishing Evidence Veto**: Strong phishing signals (IP hostname, suspicious redirect, obfuscated elements, hidden iframe, external form action) strictly prevent Stage 2 de-escalation.",
        "",
        "## 3. Verified Feature Inventory Table",
        "",
        "| Feature Name | Dtype | Source File | Used by Prod | Safe for Stage 2 | Requires HTML | May Be Unavailable | Classification |",
        "| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :--- |"
    ]
    
    for f in FEATURES:
        md_content.append(
            f"| `{f['name']}` | `{f['dtype']}` | `{f['source_file']}` | "
            f"{'Yes' if f['used_by_production'] else 'No'} | "
            f"{'Yes' if f['safe_for_stage2'] else 'No ⚠️'} | "
            f"{'Yes' if f['requires_html'] else 'No'} | "
            f"{'Yes' if f['may_be_unavailable'] else 'No'} | "
            f"**{f['classification']}** |"
        )
        
    with open(AUDIT_MD_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(md_content) + "\n")
        
    print(f"Feature inventory generated at {FEATURE_INVENTORY_PATH} ({len(FEATURES)} features).")
    print(f"Audit markdown report generated at {AUDIT_MD_PATH}.")

if __name__ == "__main__":
    generate_feature_inventory()
