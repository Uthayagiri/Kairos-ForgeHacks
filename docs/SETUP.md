# PhishGuard AI — Setup & Installation Guide

This guide provides step-by-step instructions to install, configure, and execute the entire **PhishGuard AI** platform locally.

---

## 📋 Prerequisites

Before beginning installation, ensure your environment meets the following software requirements:

- **Python**: Version `3.10` or higher (`python --version`)
- **Node.js**: Version `18.0.0` or higher (`node --version`)
- **npm**: Version `9.0.0` or higher (`npm --version`)
- **Web Browser**: Google Chrome, Chromium, or Microsoft Edge (with Developer Mode enabled for extension loading)
- **Git**: For cloning and repository tracking

---

## 🚀 1. Backend Service Setup (FastAPI & Machine Learning)

The backend provides the REST API and coordinates feature extraction and model inference.

### Step 1.1: Navigate to the Backend Directory
```bash
cd backend
```

### Step 1.2: Create and Activate a Python Virtual Environment

- **Windows PowerShell:**
  ```powershell
  python -m venv venv
  # If PowerShell blocks script execution, run: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\venv\Scripts\Activate.ps1
  ```
- **Windows Command Prompt (CMD):**
  ```cmd
  python -m venv venv
  .\venv\Scripts\activate.bat
  ```
- **macOS / Linux:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

### Step 1.3: Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 1.4: Configure Environment Variables
Copy the template configuration file:
- **Windows PowerShell:**
  ```powershell
  Copy-Item .env.example .env
  ```
- **macOS / Linux:**
  ```bash
  cp .env.example .env
  ```

The default `.env` configuration contains:
```ini
APP_NAME="Phishing Detection API"
APP_ENV="development"
DEBUG=True
HOST="127.0.0.1"
PORT=8000
MODEL_PATH="ml/models/phishing_model.joblib"
```

### Step 1.5: Start the Backend Server
Launch the FastAPI development server with automatic reload:
```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Step 1.6: Verify Backend Health
Once started, verify the service in your browser or terminal:
- **Health Check**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health) $\rightarrow$ `{"status": "ok"}`
- **Interactive OpenAPI Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Alternative Redoc Documentation**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 🌐 2. Web Dashboard Setup (React & Vite)

The frontend provides a real-time cybersecurity telemetry dashboard.

### Step 2.1: Open a New Terminal and Navigate to `frontend/`
```bash
cd frontend
```

### Step 2.2: Install Node.js Dependencies
```bash
npm install
```

### Step 2.3: Configure Frontend Environment Variables
Ensure the `.env` file points to the local backend service:
```ini
VITE_API_BASE_URL=http://127.0.0.1:8000
```
*(If missing, copy from `.env.example`: `Copy-Item .env.example .env`)*

### Step 2.4: Start the Vite Development Server
```bash
npm run dev
```

### Step 2.5: Access the Dashboard
Open your web browser and navigate to:
[http://localhost:5173](http://localhost:5173)

---

## 🧩 3. Chrome Extension Setup (Manifest V3)

The extension allows one-click active tab scanning directly from the browser toolbar.

### Step 3.1: Open Chrome Extension Management
In Google Chrome (or Edge/Brave), open a new tab and navigate to:
```
chrome://extensions/
```

### Step 3.2: Enable Developer Mode
In the top-right corner of the Extensions page, toggle the **Developer mode** switch to **ON**.

### Step 3.3: Load the Unpacked Extension
1. Click the **Load unpacked** button in the top-left menu.
2. In the file picker dialog, select the `extension/` directory from the root of this project:
   `c:\Users\Udhaya\S5_Phishing_Detector\extension`
3. Click **Select Folder**.

### Step 3.4: Pin and Use the Extension
1. Click the Chrome **Extensions puzzle icon** in your browser toolbar.
2. Click the **Pin** icon next to **PhishGuard AI — Phishing Detector**.
3. Navigate to any website (e.g., `https://en.wikipedia.org`) and click the extension icon to trigger an instant active tab analysis.

---

## 🧪 4. Running the Verification Test Suites

To verify that all backend modules, feature extractors, and integration contracts operate without error:

### Run Backend Pytest Suite
From the `backend/` directory with `venv` activated:
```powershell
pytest tests/ -v
```
*(Expected output: 80 passed tests in $\sim 14$ seconds)*

### Run Specific Test Modules
```powershell
# URL feature extractor tests
pytest tests/test_url_features.py -v

# HTML feature extractor tests
pytest tests/test_html_features.py -v

# API route and schema integration tests
pytest tests/test_api_predict.py -v

# Detection engine & risk scoring tests
pytest tests/test_detection_engine.py -v
```

---

## 🔧 5. Troubleshooting & FAQ

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **`Activate.ps1 cannot be loaded because running scripts is disabled`** | Windows PowerShell Execution Policy restriction. | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in the current PowerShell terminal. |
| **`CORS error / Failed to fetch` on frontend** | Backend is either not running or running on an unexpected port. | Ensure FastAPI backend is active at `http://127.0.0.1:8000` and check `VITE_API_BASE_URL` in `frontend/.env`. |
| **`Extension popup shows 'Cannot reach detection backend'`** | The backend server is stopped or host permissions are blocked. | Confirm `http://127.0.0.1:8000/health` responds with HTTP 200. |
| **`Model file not found error on startup`** | Working directory mismatch when executing uvicorn. | Always run uvicorn from within the `backend/` directory. |
