# AI-Based Phishing Website Detection Using URL and HTML Content Analysis

## Project Overview
This project develops an intelligent cybersecurity system designed to detect and prevent phishing attacks by analyzing both lexical and structural features of URLs alongside deep content-based features extracted from webpage HTML. Combining these two complementary analytical techniques enables robust, high-accuracy classification of malicious websites in real-time.

**Project status: Stage 1 — Foundation**

---

## Repository Structure

```
s5-phishing-detector/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI app with GET /health endpoint
│   │   ├── api/
│   │   │   └── __init__.py
│   │   ├── services/
│   │   │   └── __init__.py
│   │   └── core/
│   │       ├── __init__.py
│   │       └── config.py        # Settings loader with pydantic-settings
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── feature_extraction/
│   │   │   └── __init__.py
│   │   ├── training/
│   │   │   └── __init__.py
│   │   └── models/
│   │       └── __init__.py       # Trained model artifacts
│   ├── data/
│   │   ├── raw/
│   │   │   └── .gitkeep
│   │   └── processed/
│   │       └── .gitkeep
│   ├── tests/
│   │   └── __init__.py
│   ├── requirements.txt
│   └── .env.example
├── frontend/                     # Website frontend — built in Stage 10
│   └── README.md
├── extension/                    # Chrome extension — built in Stage 11
│   └── README.md
├── docs/                         # Documentation — added in Stage 14
│   └── README.md
├── .gitignore
└── README.md
```

---

## Environment Setup & Getting Started

### 1. Virtual Environment Setup
Inside the `backend/` directory, create and activate a Python virtual environment:

```powershell
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows PowerShell:
.\venv\Scripts\Activate.ps1

# Windows CMD:
.\venv\Scripts\activate.bat

# Linux / macOS:
source venv/bin/activate
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Environment Configuration
Copy the example environment configuration:
```powershell
# Windows PowerShell:
Copy-Item .env.example .env

# Linux / macOS:
cp .env.example .env
```

### 4. Running the Development Server
Start the FastAPI server from the `backend/` directory:
```powershell
uvicorn app.main:app --reload
```

### 5. Verification
- **Health Check Endpoint**: `http://127.0.0.1:8000/health` (Returns `{"status": "ok"}`)
- **Interactive OpenAPI Documentation**: `http://127.0.0.1:8000/docs`
