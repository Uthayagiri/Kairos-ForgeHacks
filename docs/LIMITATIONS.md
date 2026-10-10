# PhishGuard AI — System Limitations & Operational Constraints

This document provides a comprehensive, transparent audit of the known limitations, behavioral tradeoffs, and operational boundaries of the **PhishGuard AI** system (Production Model Version `2.1.0`).

---

## ⚠️ Academic Prototype Disclaimer

> [!IMPORTANT]
> **Academic Research Software Notice:**
> PhishGuard AI was developed as an academic engineering project for educational and research evaluation. It is **not** an enterprise-grade commercial endpoint security solution and must **not** be deployed as a sole, unassisted perimeter defense in mission-critical or production security environments.

---

## 1. Machine Learning & Feature Extraction Limitations

### 1.1 Probability Miscalibration vs. Recall Priority Tradeoff
- **The Issue:** The production model intentionally employs aggressive positive class re-weighting (`scale_pos_weight = 5.0`) and tree pruning to prioritize attack recall (**94.21%** on unseen domains) and minimize dangerous false negatives.
- **Consequence:** This design choice deliberately trades calibration precision for security sensitivity. The model's Brier score loss (**0.0390**) is higher than an unweighted baseline, and raw sigmoid probabilities in the ambiguous middle zone (40%–60%) skew higher than historical empirical attack frequencies.
- **Operational Interpretation:** Output confidence scores must be treated as **Monotonic Risk Scores / Ordinal Threat Rankings** (higher score = stronger threat signals and higher review priority), rather than literal calibrated empirical probabilities.

### 1.2 SPA Sensitivity & Static HTML Ingestion vs. Client-Side Rendering
- **The Issue:** Modern client-side Single-Page Applications (React, Vue, Angular) deliver minimal initial HTML shells and construct the DOM at runtime via client-side JavaScript.
- **Model Impact:** Although feature subsampling reduced top-2 link concentration from 59.26% down to **43.06%**, navigational link count remains the primary feature (`num_links` 26.47%, `num_internal_links` 16.59%). When an unrendered SPA shell is fetched statically over HTTP, its raw HTML contains 0 static links. Consequently, raw model predictions on sparse HTML shells still lean suspicious (e.g. `ps.bitsathy.ac.in` receives a raw model score of 65.43%).
- **The Tradeoff:** The detection engine applies heuristic dampening and sets `content_rendering_incomplete = True`, bounding the user-facing verdict to Medium/Suspicious.
- **Consequence:** If an adversary constructs a sophisticated phishing attack hosted on a clean-looking domain that renders a credential-harvesting form *purely through client-side JavaScript execution*, static server-side HTML parsing cannot inspect the dynamically rendered input elements, and the risk score will be dampened.

### 1.3 WAF Bot-Challenge False Positives on Raw Model Ingestion
- **The Issue:** Enterprise web infrastructure (Cloudflare, Akamai, Imperva) intercepts automated server-side HTTP fetchers with `HTTP 403 Forbidden` or JavaScript challenge pages.
- **Model Impact:** Because challenge HTML pages contain 0 navigation links, 0 forms, and minimal plain text, passing raw challenge HTML directly to the ML classifier yields an elevated phishing probability.
- **Engine Protection:** The detection engine handles this via **Degraded Mode (URL-only fallback)**, capping risk scores to Medium/Safe when HTML fetching is blocked. However, this means that for protected sites, the system relies exclusively on lexical URL signals rather than DOM inspection.

### 1.4 URL Shortener Redirect Chain & Landing Page Limitation
- **The Issue:** The feature extraction pipeline extracts lexical features from the submitted URL string (`is_shortened_url = True` based on hostname and non-service path) and fetches content directly from that input URL via a single HTTP GET request.
- **The Architectural Limitation:** The backend does **not** trace or follow HTTP 301/302 redirect chains to resolve and parse the final destination page. Consequently:
  - When an unresolvable or dead shortener URL is evaluated (or when a shortener returns an error/portal page), the engine parses the **shortener service's own landing/error page content** (e.g. Hootsuite's 113-link homepage for `ow.ly/dead_link`), rather than evaluating the intended destination attack payload.
  - While mock simulations of live destination phishing HTML with credential forms and external post actions correctly trigger **High Risk Phishing (96.0%–96.2%)**, real-world shortener phishing detection in production requires a multi-hop redirect resolution layer to extract DOM features from the true target host.
  - Standard shortener homepages (`tinyurl.com/app`, `bit.ly/pricing`) are handled via service path allowlists, but this lexical approach cannot evaluate dynamic, shortened redirect targets without active redirect following.

### 1.5 Open-Redirect & Encoded Parameter False-Positive Risk
- **The Issue:** URLs containing nested, percent-encoded destination links (e.g., `https://example.com/?redirect=https%3A%2F%2Fother.com%2F...`) trigger `has_url_encoding = True` along with elevated special character and length metrics.
- **Consequence:** In legitimate web development, percent-encoded callback parameters are standard and ubiquitous across Single Sign-On (SSO / OAuth 2.0), payment gateways, and session bouncers. The engine risks flagging legitimate enterprise login links and OAuth redirects as suspicious due to lexical parameter encoding.

### 1.6 Global `scale_pos_weight` Calibration vs. Phishing Recall Floor Trade-off
- **The Issue:** Adjusting the global `scale_pos_weight` hyperparameter shifts the tree intercept log-odds uniformly across all inputs. In controlled experiments:
  - Lowering `scale_pos_weight` to `3.5` (Candidate A) or `4.0` (Candidate B) reduced false alarms on select sites (e.g., college portal from 35.99% to 29.11%), but caused phishing recall to drop to **92.44%** and **92.70%** respectively, failing the mandatory **94.0% recall floor** and increasing missed attacks from 23 to 30 (+30.4% relative surge in false negatives).
  - Furthermore, lowering `scale_pos_weight` failed to resolve elevated risk scores on dense enterprise authentication portals like `accounts.google.com` (84.94%–87.79%) and `login.salesforce.com` (71.43%–73.56%) because these sites legitimately contain heavy password inputs, action fields, and brand keywords.
- **Recommended Future Approaches (Pending Authorization):**
  - **Institutional / Educational Domain Structural Features:** Extract explicit `.edu` / `.ac.in` / `.gov` top-level hierarchy attributes rather than relying solely on generic domain length and character distributions.
  - **Legitimate SSO / OAuth Structural Fingerprints:** Distinguish legitimate identity provider callbacks from spoofed login forms (e.g. valid SAML/OAuth response params, cross-origin action consistency).
  - **Augmentation of Legitimate Authentication Portals:** Expand training dataset representation with diverse, multi-lingual enterprise login pages and portals to teach tree splits the structural difference between legitimate SSO hubs and credential harvesting lures.

---

## 2. Network & HTML Fetching Constraints

### 2.1 Lack of Dynamic Headless Browser Execution
- **The Issue:** The backend utilizes standard HTTP requests (`requests`) and static DOM parsing (`BeautifulSoup4`).
- **Consequence:** The engine cannot:
  - Execute client-side JavaScript or observe dynamic DOM mutations.
  - Interact with multi-step forms or CAPTCHAs.
  - Detect browser-in-the-browser (BitB) simulated login windows.
  - Follow JavaScript-driven navigation (`window.location.replace`).

### 2.2 Response Size & Timeout Boundaries
- The HTTP client enforces a strict `MAX_RESPONSE_SIZE = 2 * 1024 * 1024` (2 MB) limit and a `FETCH_TIMEOUT_SECONDS = 8.0` threshold to prevent Denial-of-Service (DoS) and decompression bombs.
- Heavy modern web pages exceeding 2 MB are aborted, falling back to Degraded Mode.

---

## 3. Infrastructure & Deployment Scope Boundaries

### 3.1 Rate Limiting & Concurrency
- In the data collection module (`fetch_html.py`), rate-limiting is implemented via randomized per-worker thread delays (0.05s–0.15s) rather than a centralized per-domain token bucket.
- The FastAPI backend API does not currently enforce per-IP rate limiting or client request throttling.

### 3.2 Authentication & Authorization
- The REST API (`/predict`) is currently unauthenticated to facilitate frictionless local development between the React frontend and Chrome extension.
- Production deployments must introduce API key or JWT bearer token authentication.

### 3.3 Permissive Cross-Origin Resource Sharing (CORS)
- The FastAPI application currently sets `allow_origins=["*"]` to allow seamless local cross-origin requests from `http://localhost:5173` (Vite) and `chrome-extension://*` (Chrome MV3 popup).
- In production, CORS origins must be locked down to trusted domain white-lists.
