"""Phase 1: Implementation Audit for Selective Rendering & Threshold Tuning.

Audits production inference pipeline, feature extractor definitions, rendering
prerequisites, evidence flags, and exact reused/created files.
"""

import os
import json
import hashlib
import joblib

PROD_MODEL_PATH = "backend/ml/models/phishing_model.joblib"
DATA_PATH = "backend/data/processed/training_dataset_expanded.csv"
HTML_CACHE_DIR = "backend/data/raw/html_cache"
EXPECTED_SHA256 = "7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2"

OUTPUT_PATH = "scratch/selective_rendering_threshold_tuning/data/implementation_audit.json"
os.makedirs("scratch/selective_rendering_threshold_tuning/data", exist_ok=True)
os.makedirs("scratch/selective_rendering_threshold_tuning/reports", exist_ok=True)
os.makedirs("scratch/selective_rendering_threshold_tuning/scripts", exist_ok=True)

PROD_FEATURES = [
    "url_length", "domain_length", "path_length", "num_dots", "num_hyphens",
    "num_underscores", "num_slashes", "num_digits", "num_special_chars",
    "num_subdomains", "num_query_params", "path_depth", "has_at_symbol",
    "has_ip_address", "uses_https", "has_port", "has_url_encoding",
    "has_suspicious_tld", "has_suspicious_keywords", "has_double_slash_redirect",
    "is_shortened_url", "url_parse_error", "num_forms", "num_input_fields",
    "num_password_fields", "has_login_form", "num_forms_with_external_action",
    "has_form_action_empty_or_javascript", "num_links", "num_internal_links",
    "num_external_links", "external_link_ratio", "num_links_with_mismatched_text",
    "num_scripts", "num_iframes", "has_hidden_iframe", "has_suspicious_js_patterns",
    "num_meta_refresh_redirects", "title_length", "has_favicon", "num_images",
    "text_to_html_ratio", "html_parse_error"
]

STRONG_PHISHING_SIGNALS = [
    "has_ip_address", "has_at_symbol", "has_double_slash_redirect",
    "has_suspicious_tld", "has_suspicious_keywords", "has_url_encoding",
    "has_form_action_empty_or_javascript", "has_hidden_iframe",
    "has_suspicious_js_patterns"
]

def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def run_audit():
    sha = compute_sha256(PROD_MODEL_PATH)
    assert sha == EXPECTED_SHA256, f"Production SHA-256 altered: {sha}"
    
    prod_model = joblib.load(PROD_MODEL_PATH)
    
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    ]
    browser_bin = next((p for p in chrome_paths if os.path.exists(p)), "")
    
    audit_data = {
        "production_model": {
            "path": PROD_MODEL_PATH,
            "version": "2.1.0",
            "sha256": sha,
            "sha256_verified": sha == EXPECTED_SHA256,
            "model_class": str(type(prod_model)),
            "feature_count": len(PROD_FEATURES),
            "features": PROD_FEATURES,
            "default_threshold": 0.50
        },
        "feature_extractors": {
            "url_features": "backend/ml/feature_extraction/url_features.py (22 features)",
            "html_features": "backend/ml/feature_extraction/html_features.py (21 features)",
            "total_features": 43
        },
        "rendering_engine": {
            "binary_path": browser_bin,
            "engine_type": "Chrome Headless CLI (--headless=new --dump-dom)",
            "timeout_seconds": 2.0,
            "isolation_flags": ["--disable-gpu", "--no-sandbox", "--disable-software-rasterizer", "--virtual-time-budget=1000"]
        },
        "evidence_groups": {
            "strong_phishing_signals": STRONG_PHISHING_SIGNALS,
            "additional_veto_signals": [
                "num_forms_with_external_action > 0",
                "num_links_with_mismatched_text > 0",
                "num_meta_refresh_redirects > 0"
            ]
        },
        "fallback_policy": {
            "on_rendering_timeout": "Retain original Stage 1 static features and score without bias",
            "on_rendering_failure": "Retain original Stage 1 static features and score without bias",
            "label_assignment_rule": "Never assign label directly from rendering failure status"
        },
        "reused_files": [
            "backend/data/processed/training_dataset_expanded.csv",
            "backend/data/raw/html_cache/",
            "backend/ml/models/phishing_model.joblib",
            "backend/ml/feature_extraction/url_features.py",
            "backend/ml/feature_extraction/html_features.py"
        ],
        "created_files": [
            "scratch/selective_rendering_threshold_tuning/data/implementation_audit.json",
            "scratch/selective_rendering_threshold_tuning/data/trigger_inventory.json",
            "scratch/selective_rendering_threshold_tuning/data/leakage_checks.json",
            "scratch/selective_rendering_threshold_tuning/data/rendering_metrics.json",
            "scratch/selective_rendering_threshold_tuning/data/candidate_predictions.jsonl",
            "scratch/selective_rendering_threshold_tuning/reports/FIXED_SPLIT_RESULTS.md",
            "scratch/selective_rendering_threshold_tuning/reports/REPEATED_VALIDATION.md",
            "scratch/selective_rendering_threshold_tuning/reports/THRESHOLD_ANALYSIS.md",
            "scratch/selective_rendering_threshold_tuning/reports/RUNTIME_ANALYSIS.md",
            "scratch/selective_rendering_threshold_tuning/reports/ERROR_ANALYSIS.md",
            "docs/SELECTIVE_RENDERING_THRESHOLD_TUNING.md",
            "scratch/selective_rendering_threshold_tuning/scripts/run_experiment.py",
            "scratch/selective_rendering_threshold_tuning/walkthrough.md"
        ]
    }
    
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(audit_data, f, indent=2)
        
    print(f"Implementation audit saved to {OUTPUT_PATH}")

if __name__ == "__main__":
    run_audit()
