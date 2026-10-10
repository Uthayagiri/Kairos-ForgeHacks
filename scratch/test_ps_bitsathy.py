"""Inspect exact feature vector and model predictions for ps.bitsathy.ac.in."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path("backend").resolve()))

import json
import joblib
import pandas as pd

from app.services.detection_engine import DetectionEngine
from ml.feature_extraction import extract_url_features, extract_html_features

def inspect_ps_bitsathy():
    url = "https://ps.bitsathy.ac.in"
    print(f"Inspecting URL: {url}")
    
    engine = DetectionEngine()
    res = engine.analyze_url(url)
    
    print(f"\n--- Detection Engine Output ---")
    print(f"Status: is_phishing={res.is_phishing}, risk_level={res.risk_level}, confidence={res.confidence:.4f}")
    print(f"html_available: {res.html_available}, content_rendering_incomplete: {res.content_rendering_incomplete}")
    print(f"Indicators: {res.detected_indicators}")
    
    # Raw feature inspection
    url_feats = extract_url_features(url)
    success, html_content, error_reason, is_ssl = engine.fetch_single_html(url)
    html_feats = extract_html_features(html_content, page_url=url) if success and html_content else {}
    
    print(f"\n--- Key Raw Features Extracted ---")
    print(f"uses_https: {url_feats.get('uses_https')}")
    print(f"has_suspicious_tld: {url_feats.get('has_suspicious_tld')}")
    print(f"has_suspicious_keywords: {url_feats.get('has_suspicious_keywords')}")
    print(f"num_links: {html_feats.get('num_links')}")
    print(f"num_internal_links: {html_feats.get('num_internal_links')}")
    print(f"num_external_links: {html_feats.get('num_external_links')}")
    print(f"num_forms: {html_feats.get('num_forms')}")
    print(f"num_password_fields: {html_feats.get('num_password_fields')}")
    print(f"has_login_form: {html_feats.get('has_login_form')}")
    print(f"num_scripts: {html_feats.get('num_scripts')}")
    print(f"text_to_html_ratio: {html_feats.get('text_to_html_ratio')}")
    
    # Inspect raw model prediction without any dampening
    model = joblib.load("backend/ml/models/phishing_model.joblib")
    feature_cols = json.load(open("backend/ml/models/feature_columns.json"))
    
    combined = {}
    for k, v in url_feats.items():
        combined["url_parse_error" if k == "parse_error" else k] = int(v) if isinstance(v, bool) else v
    for k, v in html_feats.items():
        combined["html_parse_error" if k == "parse_error" else k] = int(v) if isinstance(v, bool) else v
        
    vec = pd.DataFrame([[combined.get(c, 0) for c in feature_cols]], columns=feature_cols)
    raw_prob = model.predict_proba(vec)[0, 1]
    print(f"\n--- RAW MODEL PREDICTION (Pre-Dampening) ---")
    print(f"Raw Model Phishing Probability: {raw_prob:.4f} ({raw_prob*100:.2f}%)")

if __name__ == "__main__":
    inspect_ps_bitsathy()
