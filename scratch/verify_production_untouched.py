import hashlib
import json
from pathlib import Path

prod_model_path = Path("backend/ml/models/phishing_model.joblib")
meta_path = Path("backend/ml/models/model_metadata.json")

hasher = hashlib.sha256()
with open(prod_model_path, "rb") as f:
    while chunk := f.read(65536):
        hasher.update(chunk)

current_prod_sha256 = hasher.hexdigest()
expected_sha256 = "7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2"

print(f"Current Production Model SHA-256: {current_prod_sha256}")
print(f"Expected Production Model SHA-256: {expected_sha256}")
print(f"Production Model Identical & Untouched: {current_prod_sha256 == expected_sha256}")

with open(meta_path) as f:
    meta = json.load(f)
print(f"Production Model Version: {meta.get('version')}")
print(f"Production Model Algorithm: {meta.get('algorithm')}")
