# PhishGuard AI — Real-Time AI/ML-Based Phishing Detection & Prevention System

> **A futuristic, privacy-first cybersecurity platform and Chromium browser extension** that combines 43 lexical URL heuristics, SSRF defense, live DOM inspection, and tuned XGBoost classification to detect and prevent phishing attacks in real time.

---

## 🌟 Key Highlights & Product Features

1. **Futuristic Antigravity-Inspired Web Application**:
   - **Atmospheric Dark Aesthetics**: Deep void surfaces (`#04060a`, `#080c14`), electric cyan, blue, violet, and teal neon glows, frosted glass cards, and smooth micro-animations.
   - **Interactive Cursor Spotlight**: Ambient lighting follows the pointer seamlessly without obstructing clicks or accessibility.
   - **Glowing CyberShield & Radar Visualizer**: Interactive digital shield with animated pulse rings, real-time threat radar, and mode switcher (Neutral, Safe, Suspicious, Phishing).
   - **Three Clear Outcomes**: **SAFE** (Browse with confidence), **SUSPICIOUS** (Pause & verify), **PHISHING** (Block or avoid threat).
   - **Interactive URL Scanner Workbench**: Step-by-step scanning telemetry, circular risk gauge (0–100%), calibrated uncertainty, and 3 tabbed forensic signal groups (URL Lexical, Domain & SSRF, DOM & Forms).
   - **Security Operations Dashboard**: Aggregate KPIs, risk distribution bar, threat category breakdown, searchable & filterable scan history, full forensic detail modal, demo telemetry loader, and history purge with confirmation.
   - **Interactive Architecture Pipeline & 4 Core Modules**: Detailed walkthrough of Data Collection, Feature Extraction, ML Classification, and Browser Prevention.
   - **Honest Limitations & Ethical Disclosures**: Transparent appraisal of single URL limits, HTTPS misconceptions, SPA degraded modes, and zero-logging privacy pledge.

2. **Chromium Browser Extension (Manifest V3 for Chrome & Edge)**:
   - **Active Tab URL Auto-Detection**: Instant scanning via minimal `activeTab` permission.
   - **Matching Dark Cyber Aesthetic**: Compact popup with circular risk gauge, host label, and 3 expandable signal groups.
   - **Safe Warning Interstitial (`warning/warning.html`)**: Pre-navigation interception screen for high-risk threats with a prominent *"Return to Safety"* action and deliberate override mechanisms.
   - **Configurable Settings**: Custom API endpoint (`http://127.0.0.1:8000`), auto-scan toggle, and quick dashboard launcher.
   - **Interactive Web Simulator**: Test the extension UI live directly in the web app.

3. **Defensive ML & Backend Architecture**:
   - **Tuned XGBoost 2.1.0 Model**: Persisted ensemble trained on stratified datasets with bounded calibration under degraded unreachable modes.
   - **SSRF Perimeter Defense**: Resolves domain DNS before network calls and blocks private RFC 1918 subnets, loopback hosts, and cloud metadata (`169.254.169.254`).
   - **FastAPI Endpoints**: `POST /api/analyze`, `POST /predict`, `GET /api/history`, `POST /api/history/clear`, `GET /api/stats`, `GET /health`, `GET /api/health`, and `GET /model/info`.

---

## 📂 Project Structure

```
S5_Phishing_Detector/
├── backend/                  # FastAPI REST Service & ML Pipeline
│   ├── app/                  # REST API routes, schemas, core singletons, detection services
│   │   ├── api/routes/       # /api/analyze, /predict, /api/history, /api/stats, /api/health
│   │   ├── core/             # Configuration & singleton ModelLoader
│   │   ├── services/         # DetectionEngine, HistoryService, RiskScoring
│   │   └── main.py           # FastAPI entry point & CORS configuration
│   ├── ml/                   # Data collection, feature extraction (43 features), training scripts
│   │   ├── models/           # phishing_model.joblib, model_metadata.json, feature_columns.json
│   │   └── feature_extraction/ # url_features.py, html_features.py
│   ├── tests/                # Automated Pytest suite (API, SSRF, feature extraction)
│   └── requirements.txt      # Python dependencies
├── frontend/                 # React 18 + Vite 6 Web Application
│   ├── src/
│   │   ├── components/       # Header, Footer, CyberShield, ScanInput, ResultCard, ExtensionModal...
│   │   ├── pages/            # Home, ScannerPage, DashboardPage, HowItWorksPage, TechnologyPage, AboutPage
│   │   ├── hooks/            # useScan.js (persistence, demo dataset, telemetry)
│   │   ├── api/              # predictApi.js (client with timeout & error handling)
│   │   └── index.css         # Cyber design system & cursor spotlight tokens
│   ├── package.json          # Node dependencies
│   └── vite.config.js        # Vite configuration
├── extension/                # Chromium Manifest V3 Extension (Chrome & Edge)
│   ├── manifest.json         # MV3 configuration & permissions (activeTab, storage)
│   ├── popup/                # Popup UI (popup.html, popup.css, popup.js with circular gauge)
│   ├── warning/              # Safe warning interstitial page (warning.html, warning.css, warning.js)
│   ├── background/           # Background service worker for badge telemetry & lifecycle
│   ├── icons/                # Extension icon assets (16x16, 48x48, 128x128)
│   └── README.md             # Extension installation guide
├── docs/                     # Technical Documentation Suite
└── README.md                 # Root product overview
```

---

## ⚡ Quick Start & Run Instructions

### 1. Start the Backend API (FastAPI)

```powershell
# Navigate to backend directory
cd backend

# Activate Python virtual environment
.\venv\Scripts\Activate.ps1

# (Optional) Install dependencies if needed:
# pip install -r requirements.txt

# Start the FastAPI server on port 8000
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
* Interactive API Documentation: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* Health Status Endpoint: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)

---

### 2. Start the Frontend Web Application (React + Vite)

In a new terminal:

```powershell
# Navigate to frontend directory
cd frontend

# Install dependencies (if not already installed)
npm install

# Start Vite development server
npm run dev
```
* Web Application Interface: [http://localhost:5173](http://localhost:5173)

---

### 3. Load the Browser Extension in Chrome or Edge

1. **Google Chrome**:
   - Open Chrome and navigate to `chrome://extensions/`
   - Enable **Developer mode** (toggle in the top-right corner).
   - Click **Load unpacked** (top-left).
   - Select the `extension/` folder: `c:\Users\Udhaya\S5_Phishing_Detector\extension`
   - Pin **PhishGuard AI** to your browser toolbar.

2. **Microsoft Edge**:
   - Open Edge and navigate to `edge://extensions/`
   - Enable **Developer mode** (left sidebar).
   - Click **Load unpacked** (top-right).
   - Select the `extension/` folder.

---

## 🧪 Automated Testing

### Run Backend Integration & SSRF Tests
```powershell
cd backend
.\venv\Scripts\python.exe -m pytest tests/test_api_enhanced.py
```

### Run Frontend Production Build Validation
```powershell
cd frontend
npm run build
```

---

## ⚖️ Academic Project & Privacy Notice

**PhishGuard AI** was engineered as an academic capstone and cybersecurity demonstrator. It enforces a strict **Zero Private Data Collection** policy: passwords, authentication cookies, form values, and private browsing histories are never collected or transmitted.
