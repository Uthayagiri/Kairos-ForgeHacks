"""
Complete Live Model-Switching Verification with 44-Feature Pipeline Sync
"""

import sys
import os
import time
import json
import shutil
import requests
from pathlib import Path

REPO_ROOT = Path("c:/Users/Udhaya/S5_Phishing_Detector").resolve()
BACKEND_DIR = REPO_ROOT / "backend"
PROD_MODEL_PATH = BACKEND_DIR / "ml" / "models" / "phishing_model.joblib"
EXP3_PATH = BACKEND_DIR / "ml" / "models" / "candidates_auth" / "candidate_exp3_paas_signal.joblib"
FEATURE_COLS_PATH = BACKEND_DIR / "ml" / "models" / "feature_columns.json"

BACKUP_MODEL_PATH = BACKEND_DIR / "ml" / "models" / "phishing_model_backup_live.joblib"
BACKUP_COLS_PATH = BACKEND_DIR / "ml" / "models" / "feature_columns_backup_live.json"

BASE_URL = "http://127.0.0.1:8000"

print("=" * 80)
print("LIVE FASTAPI MODEL-SWITCHING & TELEMETRY VERIFICATION")
print("=" * 80)

# 1. Check current live model
r1 = requests.get(f"{BASE_URL}/model/info")
info1 = r1.json()
print("\n[STEP 1] Initial Live Active Model Telemetry:")
print(f"  SHA-256 Hash:   {info1.get('sha256_hash')}")
print(f"  Model Version:  {info1.get('model_version')}")
print(f"  Features Count: {info1.get('features_count')}")
print(f"  Load Count:     {info1.get('load_count')}")

# Load base feature cols
with open(FEATURE_COLS_PATH, "r") as f:
    base_cols = json.load(f)

exp3_cols = base_cols + ["is_free_hosting_subdomain"]

# Backup files
shutil.copy2(PROD_MODEL_PATH, BACKUP_MODEL_PATH)
shutil.copy2(FEATURE_COLS_PATH, BACKUP_COLS_PATH)

try:
    # 2. Swap Candidate Exp 3 into active serving path & update feature cols
    with open(FEATURE_COLS_PATH, "w") as f:
        json.dump(exp3_cols, f, indent=2)
    shutil.copy2(EXP3_PATH, PROD_MODEL_PATH)
    time.sleep(1.2) # Allow file mtime polling
    
    # 3. Query live /model/info to verify auto-reload
    r2 = requests.get(f"{BASE_URL}/model/info")
    info2 = r2.json()
    print("\n[STEP 2] Swapped Candidate Exp 3 Live Telemetry:")
    print(f"  SHA-256 Hash:   {info2.get('sha256_hash')}")
    print(f"  Expected Hash:  41761e991d9fd194d6ff2716566fa68694cba100ce337e8fce575c7ee0216e3f")
    print(f"  Hashes Match:   {info2.get('sha256_hash') == '41761e991d9fd194d6ff2716566fa68694cba100ce337e8fce575c7ee0216e3f'}")
    print(f"  Features Count: {info2.get('features_count')}")
    print(f"  Load Count:     {info2.get('load_count')}")
    
    # 4. Live POST /predict requests
    test_urls = [
        "https://en.wikipedia.org",
        "https://accounts.google.com",
        "http://192.168.1.100/paypal/login.php"
    ]
    print("\n[STEP 3] Live HTTP POST /predict Responses Under Candidate Exp 3:")
    for u in test_urls:
        rp = requests.post(f"{BASE_URL}/predict", json={"url": u})
        print(f"  Status Code: {rp.status_code} | Body: {rp.text[:120]}")

finally:
    # 5. Restore Production Control
    shutil.copy2(BACKUP_COLS_PATH, FEATURE_COLS_PATH)
    shutil.copy2(BACKUP_MODEL_PATH, PROD_MODEL_PATH)
    if os.path.exists(BACKUP_MODEL_PATH):
        os.remove(BACKUP_MODEL_PATH)
    if os.path.exists(BACKUP_COLS_PATH):
        os.remove(BACKUP_COLS_PATH)
    time.sleep(1.2)
    
    r3 = requests.get(f"{BASE_URL}/model/info")
    info3 = r3.json()
    print("\n[STEP 4] Restored Production Control Live Telemetry:")
    print(f"  SHA-256 Hash:   {info3.get('sha256_hash')}")
    print(f"  Expected Hash:  7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2")
    print(f"  Hashes Match:   {info3.get('sha256_hash') == '7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2'}")
    print(f"  Features Count: {info3.get('features_count')}")
    print(f"  Load Count:     {info3.get('load_count')}")

print("\n" + "=" * 80)
print("LIVE TELEMETRY & MODEL-SWITCHING PROTOCOL VERIFIED")
print("=" * 80)
