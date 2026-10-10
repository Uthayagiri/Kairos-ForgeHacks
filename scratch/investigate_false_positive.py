"""Diagnostic script to investigate false positive classification on https://ps.bitsathy.ac.in."""

import json
import sys
from pathlib import Path

# Add backend directory to sys.path
BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.services.detection_engine import DetectionEngine
from ml.feature_extraction.url_features import extract_url_features
from ml.feature_extraction.html_features import extract_html_features, get_default_html_feature_dict
from app.core.model_loader import get_model, get_feature_columns, get_model_metadata
from ml.feature_extraction.url_feature_config import SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS

TARGET_URL = "https://ps.bitsathy.ac.in"

def run_investigation():
    print(f"============================================================")
    print(f"DIAGNOSTIC INVESTIGATION: {TARGET_URL}")
    print(f"============================================================\n")

    # 1. DetectionEngine end-to-end analysis
    print("--- 1. DetectionEngine.analyze_url() Full Output ---")
    engine = DetectionEngine()
    result = engine.analyze_url(TARGET_URL)
    result_dict = result.to_dict()
    print(json.dumps(result_dict, indent=2))

    # 2. Raw HTML Fetch Inspection
    print("\n--- 2. Live HTML Fetch Inspection ---")
    success, html_content, fetch_error, ssl_err = engine.fetch_single_html(TARGET_URL)
    print(f"Fetch Success: {success}")
    print(f"Fetch Error: {fetch_error}")
    print(f"SSL Error: {ssl_err}")
    print(f"HTML Length: {len(html_content) if html_content else 0} bytes")
    if html_content:
        print(f"HTML Snippet (first 800 chars):\n{html_content[:800]}")

    # 3. Complete Raw Feature Vectors (All 43 features)
    print("\n--- 3. Raw Feature Extraction Breakdown (43 Features) ---")
    url_feats = extract_url_features(TARGET_URL)
    html_feats = extract_html_features(html_content, TARGET_URL) if html_content else get_default_html_feature_dict(parse_error=True)
    
    combined_feats = {}
    for k, v in url_feats.items():
        col = "url_parse_error" if k == "parse_error" else k
        combined_feats[col] = int(v) if isinstance(v, bool) else v

    for k, v in html_feats.items():
        col = "html_parse_error" if k == "parse_error" else k
        combined_feats[col] = int(v) if isinstance(v, bool) else v

    feature_cols = get_feature_columns()
    print(f"Total features expected by model: {len(feature_cols)}")
    print(f"{'Feature Name':<38} | {'Value':<15} | {'Source':<6}")
    print("-" * 65)
    for col in feature_cols:
        val = combined_feats.get(col, "MISSING")
        src = "URL" if col in url_feats or col == "url_parse_error" else "HTML"
        print(f"{col:<38} | {str(val):<15} | {src:<6}")

    # 4. Specific Checks
    print("\n--- 4. Specific Target Inquiries ---")
    
    # Check suspicious keywords
    matched_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in TARGET_URL.lower()]
    print(f"SUSPICIOUS_KEYWORDS list length: {len(SUSPICIOUS_KEYWORDS)}")
    print(f"Does 'login' appear in SUSPICIOUS_KEYWORDS? {'login' in SUSPICIOUS_KEYWORDS}")
    print(f"Does URL trigger has_suspicious_keywords? {url_feats.get('has_suspicious_keywords')} (Matched: {matched_kws})")

    # Check num_subdomains
    print(f"Domain for URL: {TARGET_URL}")
    print(f"num_subdomains value: {url_feats.get('num_subdomains')} (subdomain extracted: 'ps', registered domain: 'bitsathy.ac.in')")
    print(f"num_dots value: {url_feats.get('num_dots')}")
    print(f"domain_length value: {url_feats.get('domain_length')}")

    # Check HTML login form features
    print(f"has_login_form: {html_feats.get('has_login_form')}")
    print(f"num_password_fields: {html_feats.get('num_password_fields')}")
    print(f"num_forms: {html_feats.get('num_forms')}")
    print(f"num_input_fields: {html_feats.get('num_input_fields')}")
    print(f"has_form_action_empty_or_javascript: {html_feats.get('has_form_action_empty_or_javascript')}")
    print(f"num_forms_with_external_action: {html_feats.get('num_forms_with_external_action')}")
    print(f"num_links: {html_feats.get('num_links')}")
    print(f"num_internal_links: {html_feats.get('num_internal_links')}")
    print(f"num_external_links: {html_feats.get('num_external_links')}")
    print(f"external_link_ratio: {html_feats.get('external_link_ratio')}")
    print(f"num_links_with_mismatched_text: {html_feats.get('num_links_with_mismatched_text')}")
    print(f"num_scripts: {html_feats.get('num_scripts')}")
    print(f"text_to_html_ratio: {html_feats.get('text_to_html_ratio')}")

    # 5. Model Feature Importances Cross-Reference
    print("\n--- 5. Top Model Feature Importances (from Stage 7 XGBoost) ---")
    model = get_model()
    importances = model.feature_importances_
    feat_imp = sorted(zip(feature_cols, importances), key=lambda x: x[1], reverse=True)
    
    print(f"{'Rank':<5} | {'Feature':<35} | {'Importance':<12} | {'Value on ps.bitsathy.ac.in'}")
    print("-" * 75)
    for i, (feat, imp) in enumerate(feat_imp[:15], 1):
        v = combined_feats.get(feat)
        print(f"{i:<5} | {feat:<35} | {imp:<12.5f} | {v}")

    # Probability computation breakdown
    import pandas as pd
    vec = pd.DataFrame([[combined_feats[c] for c in feature_cols]], columns=feature_cols)
    raw_proba = model.predict_proba(vec)[0]
    print(f"\nModel Raw predict_proba with Live HTML: Benign={raw_proba[0]:.4f}, Phishing={raw_proba[1]:.4f}")

    # Contrast with URL-only / Degraded Mode (html_available=False)
    default_html = get_default_html_feature_dict(parse_error=True)
    combined_degraded = {}
    for k, v in url_feats.items():
        col = "url_parse_error" if k == "parse_error" else k
        combined_degraded[col] = int(v) if isinstance(v, bool) else v
    for k, v in default_html.items():
        col = "html_parse_error" if k == "parse_error" else k
        combined_degraded[col] = int(v) if isinstance(v, bool) else v
    
    vec_deg = pd.DataFrame([[combined_degraded[c] for c in feature_cols]], columns=feature_cols)
    raw_proba_deg = model.predict_proba(vec_deg)[0]
    print(f"Model Raw predict_proba with Degraded / Zero HTML: Benign={raw_proba_deg[0]:.4f}, Phishing={raw_proba_deg[1]:.4f}")

    # Also test what happens if HTML had 20 links like a traditional server-rendered benign page
    mock_rendered_html = dict(combined_feats)
    mock_rendered_html["num_links"] = 25
    mock_rendered_html["num_internal_links"] = 20
    mock_rendered_html["num_external_links"] = 5
    mock_rendered_html["num_images"] = 4
    mock_rendered_html["text_to_html_ratio"] = 0.25
    vec_mock = pd.DataFrame([[mock_rendered_html[c] for c in feature_cols]], columns=feature_cols)
    raw_proba_mock = model.predict_proba(vec_mock)[0]
    print(f"Hypothetical Rendered (num_links=25, internal=20): Benign={raw_proba_mock[0]:.4f}, Phishing={raw_proba_mock[1]:.4f}")

if __name__ == "__main__":
    run_investigation()
