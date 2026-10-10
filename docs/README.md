# PhishGuard AI — Technical Documentation Index

Welcome to the comprehensive technical documentation for **PhishGuard AI**, an intelligent machine learning cybersecurity system for real-time phishing website detection.

---

## 📖 Documentation Directory

| Document | Description |
| :--- | :--- |
| **[Architecture Overview](file:///c:/Users/Udhaya/S5_Phishing_Detector/docs/ARCHITECTURE.md)** | End-to-end system design, component breakdown, data flow diagrams, and directory hierarchy. |
| **[Setup & Installation Guide](file:///c:/Users/Udhaya/S5_Phishing_Detector/docs/SETUP.md)** | Step-by-step instructions to install, configure, and run the Backend, Web Dashboard, and Chrome Extension. |
| **[Methodology & Engineering](file:///c:/Users/Udhaya/S5_Phishing_Detector/docs/METHODOLOGY.md)** | Data sources, curation, deep-link augmentation, 43-feature extraction pipeline, and the 3 core bias resolutions. |
| **[Evaluation & Results](file:///c:/Users/Udhaya/S5_Phishing_Detector/docs/RESULTS.md)** | Verified test metrics, confusion matrix analysis, cross-validation stability, feature importance, and qualitative testing. |
| **[System Limitations](file:///c:/Users/Udhaya/S5_Phishing_Detector/docs/LIMITATIONS.md)** | Honest audit of operational constraints, WAF impacts, SPA tradeoffs, shortener homepages, and OAuth redirect risks. |
| **[Future Improvements](file:///c:/Users/Udhaya/S5_Phishing_Detector/docs/FUTURE_WORK.md)** | Roadmap for headless browser rendering (Playwright), OAuth parameter parsing, automated feed ingestion, and production MLOps. |

---

## 🎯 Project Overview

Phishing attacks remain the primary initial access vector for cyber adversaries. Traditional defense mechanisms rely heavily on static blacklists (which lag behind zero-hour threats) or surface-level URL heuristics (which produce high false-positive rates on modern deep links and complex web applications).

**PhishGuard AI** solves this challenge through a **dual-layer analytical pipeline**:
1. **Lexical & Structural URL Feature Extraction:** 22 engineered features capturing length, character distributions, domain entropy, obfuscation, suspicious TLDs, and sensitive authentication keywords.
2. **Deep HTML Content & DOM Inspection:** 21 engineered features analyzing credential forms, external action targets, internal vs. external hyperlink ratios, obfuscated JavaScript patterns, hidden iframe structures, and unrendered SPA containers.
3. **Calibrated Machine Learning Classification:** An optimized XGBoost model ($F_1 = 0.9431$, $\text{ROC-AUC} = 0.9955$, $\text{Recall} = 0.9687$) with heuristic risk scoring that seamlessly handles network degradation and single-page applications.

---

## 🛠️ Technology Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TECH STACK SUMMARY                             │
├──────────────────────┬──────────────────────────────────────────────────────┤
│ Backend API          │ Python 3.10+, FastAPI, Uvicorn, Pydantic v2          │
│ Machine Learning     │ XGBoost, scikit-learn, pandas, NumPy, joblib         │
│ HTML / Web Parsing   │ BeautifulSoup4, lxml, requests, urllib3              │
│ Web Dashboard        │ React 18, Vite 5, Tailwind CSS, Lucide Icons         │
│ Browser Extension    │ Chrome Extension Manifest V3, Vanilla JS, Chrome API │
│ Testing & QA         │ Pytest, pytest-asyncio, Chrome Extension Test Suite  │
└──────────────────────┴──────────────────────────────────────────────────────┘
```

---

## 🖥️ User Interface Overview

### 1. Web Intelligence Dashboard (`frontend/`)
- **Interactive Scanning Engine:** Direct URL input with instant keyboard triggers, sample URL chips, and live input validation.
- **Visual Risk Telemetry:** Circular radial score gauge with color-coded risk levels (Safe, Low, Medium, High).
- **Categorized Threat Indicators:** Human-readable explanations for both URL-based indicators and live DOM observations.
- **SPA Awareness Banner:** Contextual warning banners when client-side Single-Page Applications (React/Vue/Angular) are detected with unrendered content.
- **Persistent Scan History:** Local storage session history allowing rapid recall of previous scan results.

### 2. Chrome Security Extension (`extension/`)
- **Manifest V3 Architecture:** Built with non-persistent service workers and fine-grained permissions (`activeTab`).
- **One-Click Active Tab Scanning:** Automatically reads the current browser tab URL and initiates immediate inspection.
- **Badge & Status Alerts:** Real-time visual risk badges, warning callouts for degraded mode, and distinct notices for unrendered SPAs.
- **Monotonic Scan Sequencing:** Strict transaction sequencing (`scanId`) preventing asynchronous race conditions during rapid navigation.
