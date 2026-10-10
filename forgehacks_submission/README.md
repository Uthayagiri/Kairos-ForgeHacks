# PhishGuard AI — ForgeHacks Hackathon Submission Portfolio

> **Real-Time AI/ML-Based Phishing Detection & Prevention System**  
> Developed for ForgeHacks 2026 • Verified Codebase, Machine Learning Pipeline & Chromium Manifest V3 Extension

---

## 📁 Complete Submission Evidence Directory

This submission folder contains **10 publication-grade demonstration images** (1920×1080, 16:9), **5 high-definition video demonstrations** (1080p @ 30 FPS MP4), and detailed architectural reports.

```
forgehacks_submission/
├── 01_system_architecture.png              # System Topology & Architecture
├── 02_detection_workflow.png               # 10-Stage Detection Pipeline Flowchart
├── 03_real_application.png                 # Web App Scanner & SecOps Dashboard
├── 04_browser_extension.png                # Chromium Manifest V3 Extension Board
├── 05_reporting_blacklist.png              # Threat Intel & Blacklist Lifecycle
├── 06_legitimate_url_scan.png              # Legitimate URL Scan (0.4% Safe)
├── 07_suspicious_url_scan.png              # Suspicious URL Scan (48.0% Degraded Mode)
├── 08_high_risk_detection.png              # High-Risk SSRF Phishing Attack (91.1%)
├── 09_browser_extension_scan.png           # Browser Extension Tab Scan (0.4%)
├── 10_pre_navigation_security_warning.png  # Pre-Navigation Interstitial (98.6%)
├── README.md                               # Complete Submission Index
├── README_additional_images.md             # Technical Evidence for Images 06-10
├── VIDEO_DEMO_REPORT.md                    # Technical Report for Demonstration Videos
└── videos/
    ├── 01_web_legitimate_scan.mp4          # Web Scanner: Legitimate Target (45s)
    ├── 02_web_suspicious_high_risk_scans.mp4 # Web Scanner: Suspicious vs High-Risk (60s)
    ├── 03_extension_url_scanning.mp4       # Browser Extension: Multi-Tab Scan (60s)
    ├── 04_extension_pre_navigation_warning.mp4 # Extension: Pre-Nav Interception (45s)
    └── 05_full_system_demonstration.mp4    # Full End-to-End System Walkthrough (90s)
```

---

## 🎥 Demonstration Video Suite

| File Name | Video Title | Target / Fixture | Duration | Resolution / FPS | Verdict & Score |
| :--- | :--- | :--- | :---: | :---: | :---: |
| [`01_web_legitimate_scan.mp4`](./videos/01_web_legitimate_scan.mp4) | **Legitimate Website Scan** | `https://docs.python.org/3/library/index.html` | **45.0s** | 1920×1080 @ 30fps | `SAFE` (**0.4%**) |
| [`02_web_suspicious_high_risk_scans.mp4`](./videos/02_web_suspicious_high_risk_scans.mp4) | **Suspicious & High-Risk Scans** | Part A: `unverified-fast-news.biz`<br>Part B: `192.168.1.50/secure-login` | **60.0s** | 1920×1080 @ 30fps | Part A: `48.0%`<br>Part B: `91.1%` |
| [`03_extension_url_scanning.mp4`](./videos/03_extension_url_scanning.mp4) | **Browser Extension In Action** | Active Chromium Multi-Tab Workflow | **60.0s** | 1920×1080 @ 30fps | `0.4%` / `48%` / `91%` |
| [`04_extension_pre_navigation_warning.mp4`](./videos/04_extension_pre_navigation_warning.mp4) | **Pre-Navigation Interception** | `paypal-security-update...login.top` | **45.0s** | 1920×1080 @ 30fps | `98.6%` (Blocked) |
| [`05_full_system_demonstration.mp4`](./videos/05_full_system_demonstration.mp4) | **Complete PhishGuard AI Demo** | Full System & Telemetry Walkthrough | **90.0s** | 1920×1080 @ 30fps | Multi-Tier End-to-End |

---

## 📸 Technical Demonstration Images

| File Name | Visual Title | Core Focus | Implementation Status |
| :--- | :--- | :--- | :--- |
| [`01_system_architecture.png`](./01_system_architecture.png) | **Complete System Architecture** | Full-stack topology, client layer, API gateway, dual-branch extractors, tuned XGBoost model, SSRF perimeter guard. | **Fully Implemented & Verified** |
| [`02_detection_workflow.png`](./02_detection_workflow.png) | **Real Phishing Detection Pipeline** | 10-stage sequential & parallel execution flowchart from URL submission to calibrated risk scoring. | **Fully Implemented & Verified** |
| [`03_real_application.png`](./03_real_application.png) | **Live Application & Scanner Result** | Web application screenshot (`http://localhost:5173`) showing live scanning, circular gauge, and SecOps dashboard. | **Fully Implemented & Verified** |
| [`04_browser_extension.png`](./04_browser_extension.png) | **Chromium Extension & Prevention** | Technical evidence board of Manifest V3 extension, active tab auto-detection, and warning screen. | **Fully Implemented & Verified** |
| [`05_reporting_blacklist.png`](./05_reporting_blacklist.png) | **Threat Intel & Blacklist Lifecycle** | Transparent matrix contrasting the verified ML engine with the planned community blacklist sync. | **Section 1: Verified**<br>**Section 2: Roadmap** |
| [`06_legitimate_url_scan.png`](./06_legitimate_url_scan.png) | **Legitimate URL Scan** | Authentic Python docs live scan (`0.4%` risk score), dual-branch DOM analysis, TLS 1.3 verification. | **Fully Implemented & Verified** |
| [`07_suspicious_url_scan.png`](./07_suspicious_url_scan.png) | **Suspicious URL Scan** | Unverified domain under degraded mode (`48.0%` calibrated cap), plain HTTP transport alert. | **Fully Implemented & Verified** |
| [`08_high_risk_detection.png`](./08_high_risk_detection.png) | **High-Risk Phishing Detection** | SSRF perimeter defense blocking RFC 1918 private IP (`91.1%` risk score), auth keyword detection. | **Fully Implemented & Verified** |
| [`09_browser_extension_scan.png`](./09_browser_extension_scan.png) | **Browser Extension In Browser** | Extension popup in active browser session verifying legitimate origin with backend connectivity. | **Fully Implemented & Verified** |
| [`10_pre_navigation_security_warning.png`](./10_pre_navigation_security_warning.png) | **Pre-Navigation Warning Interstitial** | Security interstitial intercepting `98.6%` phishing lure before page rendering with Return to Safety action. | **Fully Implemented & Verified** |

---

## 🛠️ Verification & Benchmark Summary

- **Backend Operational Status:** FastAPI on `http://127.0.0.1:8000` (`87/87` pytest tests passing).
- **Frontend Operational Status:** React 18 + Vite on `http://localhost:5173`.
- **Browser Extension Status:** Chromium Manifest V3 (`extension/`) with service worker & activeTab API.
- **Inference Latency:** Sub-65ms average response time for dual-branch feature extraction and XGBoost classification.
