# PhishGuard AI — Future Work & Roadmap

This document outlines proposed engineering enhancements, research directions, and architectural improvements to advance **PhishGuard AI** from an academic prototype to an enterprise-grade defense platform.

---

## 1. Dynamic Headless Browser Rendering (Playwright / Puppeteer)

### 🎯 Primary Objective: Eliminate the SPA-Shell Limitation
The single most impactful architectural enhancement is replacing static HTTP fetching (`requests`) with an asynchronous headless browser engine (e.g., **Playwright** or **Puppeteer**):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       HEADLESS BROWSER ENHANCEMENT ARCHITECTURE             │
├─────────────────────────────────────────────────────────────────────────────┤
│  Target URL ──► Headless Chromium Instance (Playwright)                     │
│                 ├── Executes Client-Side JavaScript (React / Vue / Angular) │
│                 ├── Waits for Network Idle / DOM Hydration Event            │
│                 ├── Renders Full Dynamic DOM (Forms, Password Inputs)       │
│                 └── Captures Post-Hydration HTML Snapshot                   │
│                                    │                                        │
│                                    ▼                                        │
│                  Feature Extraction Pipeline (43 Features)                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Benefits:
- **Full SPA Inspection:** Enables extraction of dynamically generated login forms and credential inputs constructed by client-side JavaScript.
- **Dynamic Obfuscation De-cloaking:** Evaluates obfuscated scripts (`eval()`, dynamic DOM injections) in a secure sandbox before feature extraction.
- **Redirection Chain Resolution:** Traces client-side `window.location` redirects to capture the final landing destination.

---

## 2. Advanced Parameter Parsing & OAuth Flow Awareness

### 🎯 Objective: Resolve Open-Redirect & Encoded Parameter False Positives
To prevent false alarms on legitimate enterprise Single Sign-On (SSO), OAuth 2.0, and payment gateways, parameter parsing should be made semantically aware:

1. **Parameter Structure Deconstruction:** Inspect query parameters specifically keyed as `redirect_uri`, `return_url`, `next`, `target`, or `callback`.
2. **Relative & Subdomain Validation:** Verify whether the target destination belongs to the same parent domain or an approved enterprise identity provider (e.g., `login.microsoftonline.com`, `accounts.google.com`).
3. **Decoupled Scoring:** Evaluate lexical features on the primary domain and target destination separately rather than treating percent-encoding syntax as an inherent attack indicator.

---

## 3. Path-Aware URL Shortener Intelligence & Unshortening

### 🎯 Objective: Eliminate False Positives on Shortener Homepages
1. **Path-Aware Heuristic:** Differentiate root domain paths (e.g., `tinyurl.com`, `tinyurl.com/app`, `bit.ly/pricing`) from short alphanumeric redirection hashes (e.g., `bit.ly/3xY7k9A`).
2. **Automated Headless Link Expansion:** Perform lightweight HTTP `HEAD` requests (`allow_redirects=True`) with safe timeout limits to unshorten redirect links and inspect the true destination domain.

---

## 4. Production API Hardening & Distributed Scalability

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PRODUCTION DEPLOYMENT TOPOLOGY                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  Clients (Web / Extension)                                                  │
│        │                                                                    │
│        ▼ HTTPS                                                              │
│  API Gateway / Nginx Reverse Proxy (SSL Termination, Rate Limiting)         │
│        │                                                                    │
│        ▼ Load Balancer                                                      │
│  FastAPI Worker Cluster (Gunicorn / Uvicorn Workers)                        │
│        ├── Redis Caching Tier (Caches recent scan results by SHA-256 hash)  │
│        └── Celery Task Queue (Asynchronous heavy browser rendering)         │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Key Production Enhancements:
- **Token-Bucket Rate Limiting:** Enforce per-IP and per-API-key request throttling (via `slowapi` or Redis token bucket) to protect backend resources.
- **Authentication & RBAC:** Implement JWT bearer tokens or API keys for enterprise client authorization.
- **Locked-Down CORS:** Restrict CORS headers to verified client domains.
- **Distributed Scan Caching:** Store scan outcomes in Redis using canonical URL hashes with configurable TTLs (e.g., 10 minutes) to eliminate redundant crawling.

---

## 5. Visual Brand Recognition & Computer Vision (CV) Pipeline

### 🎯 Objective: Zero-Hour Brand Impersonation Defense
Phishers frequently deploy CSS obfuscation, canvas rendering, or SVG layering to bypass text-based HTML feature extraction. A computer vision pipeline would augment DOM analysis:

1. **Viewport Screenshot Capture:** Capture a high-resolution viewport image during headless rendering.
2. **Perceptual Hashing (pHash):** Compare visual snapshots against a database of major targeted brands (Apple, Microsoft, PayPal, Netflix, Chase).
3. **Logo Detection CNN:** Employ a lightweight object detection model (YOLOv8-nano) to detect brand logos and compare the detected brand against the registered domain name.

---

## 6. Continuous MLOps & Threat Feed Retraining Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             CONTINUOUS MLOPS PIPELINE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  Daily Feeds (PhishTank, OpenPhish, URLhaus, Tranco)                        │
│        │                                                                    │
│        ▼                                                                    │
│  Automated Ingestion & HTML Crawler ──► Feature Extraction Engine           │
│                                                │                            │
│                                                ▼                            │
│  Drift Detection (Evidently AI / KS-Test) ──► Automated Retraining Pipeline │
│                                                │                            │
│                                                ▼                            │
│  Shadow Model Evaluation ──► Automated Model Registry & Production Rollout   │
└─────────────────────────────────────────────────────────────────────────────┘
```

- **Concept Drift Detection:** Monitor shifting feature distributions (e.g., emergence of new malicious TLDs or obfuscation techniques).
- **Automated Retraining:** Automatically retrain XGBoost models on a weekly cadence with verified fresh attack telemetry.
