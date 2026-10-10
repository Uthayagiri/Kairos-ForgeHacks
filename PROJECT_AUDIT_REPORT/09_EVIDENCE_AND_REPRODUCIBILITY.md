# PhishGuard AI — Evidence, Reproducibility & Audit Log

## 1. Audit Environment & Software Stack

All audit findings, empirical tests, and static code analyses were executed in the following verified environment:

- **Host Operating System:** Microsoft Windows 11 Pro (build architecture: AMD64)
- **Local Time of Audit:** October 2026
- **Workspace Directory:** `c:\Users\Udhaya\S5_Phishing_Detector`
- **Python Runtime:** Python 3.13.14 (`backend\venv\Scripts\python.exe`)
- **Key Python Packages:**
  - `fastapi` 0.115.0
  - `uvicorn` 0.30.6
  - `xgboost` 2.1.0
  - `scikit-learn` 1.5.1
  - `joblib` 1.4.2
  - `beautifulsoup4` 4.12.3
  - `requests` 2.32.3
  - `pytest` 9.1.1
- **Node.js & Frontend Stack:**
  - `vite` 6.4.3
  - `react` 18.3.1
  - `tailwindcss` 3.4.17
- **Browser Environment:** Google Chrome Application (Version 122+ / 64-bit located at `C:\Program Files\Google\Chrome\Application\chrome.exe`)

---

## 2. Distinction Between Verified Evidence, Static Review & Assumptions

| Finding / Statement | Method of Verification | Evidence Reference |
| :--- | :---: | :--- |
| **87 Automated Backend Tests Pass (100%)** | **Empirically Executed** | Task `task-188` log: 87 passed in 120.19s via `pytest tests/` |
| **Event Loop Blocking DoS (TC-09 / TC-10)** | **Empirically Executed** | Task `task-208` log: Unresolvable DNS lookup caused 10.0s client timeout & blocked queue |
| **Active Production Model Architecture** | **Verified Artifact** | `backend/ml/models/model_metadata.json` (Candidate A4, XGBoost 2.1.0) |
| **Production Model SHA-256 Hash** | **Cryptographic Hash Check**| `7a80ec64d1d39530f0283bd62758de990f71fe8fe0e92933fa0ada1ea904b0c2` |
| **Zero Domain Overlap in Evaluation** | **Static Code & Data Review**| `deploy_candidate_a4.py` lines 19, 33-56 (`GroupShuffleSplit` on `reg_domain`) |
| **Link Count Feature Dominance (43.06%)** | **Verified Metadata** | `model_metadata.json` (`num_links`: 0.2647, `num_internal_links`: 0.1659) |
| **Advisory-Only Extension (No Blocking)** | **Static Code Review** | `extension/background/service-worker.js` (lines 6-37) & `popup.js` (lines 161-177) |
| **SSRF Filter Bypass via Redirects** | **Static Code Analysis** | `detection_engine.py` (lines 212 & 232: `allow_redirects=True`) |
| **Wildcard CORS on All Endpoints** | **Static Code Review** | `backend/app/main.py` lines 63-69 (`allow_origins=["*"]`) |
| **False Positive on MDN Security Page** | **Empirically Executed** | Task `task-208` log: TC-13 classified as `status: suspicious`, score: `47.4%` |
| **Single Page Application Bounding** | **Empirically Executed** | Task `task-208` log: TC-15 correctly flagged `content_rendering_incomplete: true`, score: `48.0%` |
| **In-The-Wild Evasion on Real Malware** | **Theoretical Inference** | Deduced from lack of headless JS execution and static regex parsing; real live malware was not attacked per audit ethics rules. |

---

## 3. Exact Commands Executed During Audit

### 1. Verification of Active Ports
```powershell
Get-NetTCPConnection -LocalPort 8000, 5173 -ErrorAction SilentlyContinue | Format-Table -Property LocalAddress, LocalPort, State
```
*Output:* Both ports confirmed listening on `127.0.0.1:8000` (FastAPI) and `127.0.0.1:5173` (Vite).

### 2. Execution of Automated Backend Pytest Suite
```powershell
cd c:\Users\Udhaya\S5_Phishing_Detector\backend
.\venv\Scripts\python.exe -m pytest tests/
```
*Full Output Transcript:*
```text
============================= test session starts =============================
platform win32 -- Python 3.13.14, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\Udhaya\S5_Phishing_Detector\backend
plugins: anyio-4.15.1
collected 87 items

tests\test_api_enhanced.py ....                                          [  4%]
tests\test_api_predict.py ...................                            [ 26%]
tests\test_build_training_dataset.py ....                                [ 31%]
tests\test_crawl_legitimate_deep_links.py ....                           [ 35%]
tests\test_detection_engine.py ................                          [ 54%]
tests\test_fetch_html.py ......                                          [ 60%]
tests\test_html_features.py ...........                                  [ 73%]
tests\test_stale_model_protection.py ...                                 [ 77%]
tests\test_train_baseline_models.py ....                                 [ 81%]
tests\test_tune_and_finalize_model.py ......                             [ 88%]
tests\test_url_features.py ..........                                    [100%]

============================== warnings summary ===============================
venv\Lib\site-packages\fastapi\testclient.py:1: StarletteDeprecationWarning
venv\Lib\site-packages\starlette\testclient.py:53: DeprecationWarning
tests/test_api_enhanced.py::test_api_history_and_stats: InsecureRequestWarning: Unverified HTTPS request to host 'example.com'
================= 87 passed, 3 warnings in 120.19s (0:02:00) ==================
```

### 3. Execution of Empirical Scenario Harness
```powershell
.\backend\venv\Scripts\python.exe C:\Users\Udhaya\.gemini\antigravity-ide\brain\9a908033-1bdc-436b-9f7c-e0e33d8adb61\scratch\test_audit_scenarios.py
```
*Output Summary:* All 15 controlled test payloads executed against the live `/api/analyze` route; raw responses captured in task log `task-208.log`.

---

## 4. Key File Locations & Code References

- **FastAPI Entry Point & CORS Setup:** [backend/app/main.py:L41-L69](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/app/main.py#L41-L69)
- **API Route Handlers & Telemetry:** [backend/app/api/routes/predict.py:L33-L128](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/app/api/routes/predict.py#L33-L128)
- **SSRF Filter & Synchronous Fetcher:** [backend/app/services/detection_engine.py:L52-L89](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/app/services/detection_engine.py#L52-L89) & [L197-L278](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/app/services/detection_engine.py#L197-L278)
- **Degraded Bounding & Risk Thresholds:** [backend/app/services/risk_scoring.py:L80-L134](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/app/services/risk_scoring.py#L80-L134)
- **URL Feature Extractor (22 features):** [backend/ml/feature_extraction/url_features.py:L60-L199](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/ml/feature_extraction/url_features.py#L60-L199)
- **HTML Feature Extractor (21 features):** [backend/ml/feature_extraction/html_features.py:L109-L340](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/ml/feature_extraction/html_features.py#L109-L340)
- **Model Metadata & Feature Importances:** [backend/ml/models/model_metadata.json:L1-L56](file:///c:/Users/Udhaya/S5_Phishing_Detector/backend/ml/models/model_metadata.json#L1-L56)
- **Extension Manifest V3 Declarations:** [extension/manifest.json:L1-L34](file:///c:/Users/Udhaya/S5_Phishing_Detector/extension/manifest.json#L1-L34)
- **Extension Service Worker (Badge Only):** [extension/background/service-worker.js:L1-L38](file:///c:/Users/Udhaya/S5_Phishing_Detector/extension/background/service-worker.js#L1-L38)
- **Extension Popup Controller:** [extension/popup/popup.js:L58-L298](file:///c:/Users/Udhaya/S5_Phishing_Detector/extension/popup/popup.js#L58-L298)
- **Safe Warning Interstitial Page:** [extension/warning/warning.js:L1-L79](file:///c:/Users/Udhaya/S5_Phishing_Detector/extension/warning/warning.js#L1-L79)
