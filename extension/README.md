# PhishGuard AI — Chromium Browser Extension (Manifest V3)

A lightweight, real-time Chromium extension for Chrome & Microsoft Edge powered by the PhishGuard AI Machine Learning engine.

---

## 🛡️ Overview

The **PhishGuard AI Browser Extension** provides real-time website inspection and phishing defense:
1. **Active Tab Inspection**: Queries the active tab URL using Chrome's secure `activeTab` permission.
2. **ML & Heuristic Classification**: Sends the target URL to the PhishGuard FastAPI backend (`POST /api/analyze` / `/predict`).
3. **Circular Risk Indicator**: Displays an animated circular risk gauge (0–100%), status badge (**Safe**, **Suspicious**, or **Phishing**), and actionable advice.
4. **3 Signal Breakdown Accordions**:
   - **URL Signals**: HTTPS security, domain length, subdomain depth, keyword deception, entropy.
   - **Domain & SSRF**: Raw IP host detection, TLD risk classification, SSRF perimeter defense.
   - **DOM & Form Signals**: Live HTML status, password input count, external form action ratio, SPA shell flag.
5. **Safe Warning Interstitial (`warning/warning.html`)**: Safe landing screen with a prominent *"Return to Safety"* button and a deliberate override mechanism.
6. **Configurable Settings**: Custom API endpoint URL (`http://127.0.0.1:8000`), auto-scan toggle, and quick dashboard launch.

---

## 📂 Extension Directory Structure

```
extension/
├── manifest.json              # Manifest V3 configuration & permissions
├── background/
│   └── service-worker.js      # Background worker for badge telemetry & lifecycle
├── icons/
│   ├── icon16.png             # 16x16 toolbar icon
│   ├── icon48.png             # 48x48 extension management icon
│   └── icon128.png            # 128x128 webstore / high-res icon
├── popup/
│   ├── popup.html             # Popup DOM structure & view containers
│   ├── popup.css              # Cyber-themed dark mode styling & circular gauge
│   └── popup.js               # Tab inspection, API client, & view renderer
├── warning/
│   ├── warning.html           # Safe interstitial warning page
│   ├── warning.css            # Interstitial warning page styles
│   └── warning.js             # Override controller & history-back handler
└── README.md                  # Setup & usage documentation
```

---

## 🔒 Permissions & Security Architecture

The extension follows the principle of least privilege:
- **`activeTab`**: Accesses active tab URL *only* when the user triggers the popup or safety check.
- **`storage`**: Persists local extension preferences (API base URL, auto-scan).
- **`host_permissions`**: Allows communication with the local PhishGuard FastAPI backend (`http://127.0.0.1:8000/*`, `http://localhost:8000/*`).
- **Zero Data Harvesting**: Never collects passwords, session cookies, auth tokens, or private browsing history.

---

## 🚀 How to Load and Test in Chrome and Edge

### Step 1: Start the Backend and Frontend

In your terminal:

```bash
# In backend folder
cd backend
.\venv\Scripts\activate
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Verify backend health at: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health) (returns `{"status": "ok"}`).

### Step 2: Load Unpacked Extension in Chrome or Edge

1. **Google Chrome**:
   - Navigate to `chrome://extensions/`
   - Enable **Developer mode** (top-right toggle switch)
   - Click **Load unpacked** (top-left)
   - Select the `extension/` folder: `c:\Users\Udhaya\S5_Phishing_Detector\extension`

2. **Microsoft Edge**:
   - Navigate to `edge://extensions/`
   - Enable **Developer mode** (left sidebar toggle)
   - Click **Load unpacked** (top-right)
   - Select the `extension/` folder.

3. Pin the **PhishGuard AI** shield icon to your browser toolbar.

### Step 3: Test Real-Time Analysis

1. Visit any website (e.g. `https://en.wikipedia.org` or `https://github.com`).
2. Click the **PhishGuard AI** toolbar icon.
3. The popup evaluates the active tab and presents the circular risk meter and signals.
4. Test custom URLs or simulated threats via the 🔍 manual search panel.
