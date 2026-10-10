# PhishGuard AI — Limitations, Evasion Scenarios & False Classifications

## 1. Verified False-Positive Scenarios

### False Positive 1: Legitimate Technical Documentation & Security Articles
- **Observed Case:** `https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS` (TC-13)
- **Assigned Verdict:** **47.4% ("Suspicious Domain")**  
- **Action Recommended to User:** *"EXERCISE CAUTION: Inspect the domain address bar carefully."*
1. **Why it exists:**  
   The lexical feature extractor checks `any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS)`. The word `"security"` is hardcoded in `SUSPICIOUS_KEYWORDS`. When the target URL is evaluated in degraded or URL-only mode, the model has no top-1M domain whitelist and assumes the URL is attempting authentication deception.
2. **Confirmation Status:** **CONFIRMED** (Reproduced live in TC-13 with HTTP 200).
3. **Practical Impact:**  
   Users browsing reputable documentation (MDN, GitHub Security advisories, OWASP guides) will receive spurious security warnings, creating alert fatigue.
4. **How encountered:** Any legitimate URL containing `"login"`, `"verify"`, `"account"`, or `"security"` in its path.
5. **Realistic Mitigation:**  
   Integrate a Tranco Top 10,000 root domain whitelist. If the registered domain is verified as an authoritative top-tier domain with valid TLS, suppress generic lexical keyword penalties unless explicit visual impersonation is detected.
6. **Priority:** **HIGH (P2)**

---

### False Positive 2: Single-Page Applications (SPAs) & Minimalist Landing Pages
- **Observed Case:** `https://modern-spa-app.com/dashboard` (TC-15)
- **Assigned Verdict:** **48.0% ("Suspicious Domain")**
1. **Why it exists:**  
   Client-side JavaScript applications (React, Angular, Vue, Svelte) deliver an initial HTML payload with `<div id="root"></div>` and `<script src="...">`. Static BeautifulSoup parsing sees zero anchor links, zero form tags, and near-zero text content. The XGBoost model heavily equates low link counts (`num_links < 5`) with phishing kits.
2. **Confirmation Status:** **CONFIRMED** (Reproduced live in TC-15).
3. **Practical Impact:**  
   Modern cloud applications, SaaS dashboards, and Web3 frontends are systematically flagged as Suspicious upon initial load.
4. **How encountered:** Normal browsing on modern web applications.
5. **Realistic Mitigation:**  
   Deploy an asynchronous headless rendering worker (Playwright or Chromium headless) with a 2-second render window for client-side JavaScript, or distinguish low-link SPAs using script bundle heuristics.
6. **Priority:** **HIGH (P2)**

---

### False Positive 3: Multi-Part ccTLDs Subdomain Miscounting
- **Observed Case:** `https://www.bbc.co.uk/news` or `https://university.ac.in/portal`
1. **Why it exists:**  
   `url_features.py` calculates subdomains via:  
   `num_subdomains = max(0, len(hostname.split(".")) - 2)`  
   It assumes every internet domain has a single-part TLD (`.com`, `.org`). For two-part ccTLDs (`.co.uk`, `.ac.in`, `.com.au`, `.gov.uk`), `bbc.co.uk` has 3 parts (`bbc`, `co`, `uk`), resulting in `num_subdomains = 1` instead of `0`.
2. **Confirmation Status:** **CONFIRMED** via static code inspection of `backend/ml/feature_extraction/url_features.py` (Line 116).
3. **Practical Impact:**  
   Artificially inflates the subdomain count for UK, Australian, Indian, and Japanese domains by +1, biasing international sites toward higher risk.
4. **How encountered:** Any user visiting international domains with multi-part public suffixes.
5. **Realistic Mitigation:** Replace manual string splitting with the industry-standard `tldextract` library, which evaluates the Public Suffix List (PSL).
6. **Priority:** **MEDIUM (P3)**

---

## 2. Verified False-Negative & Evasion Scenarios

### False Negative 1: Phishing Kits Hosted on Reputable PaaS & Cloud Platforms
- **Attack Scenario:** Phishing lure hosted on `https://docs.google.com/forms/...`, `https://forms.office.com/...`, `https://canva.com/site/...`, or `https://notion.site/...`.
1. **Why it exists:**  
   The domain lexical features reflect prestigious domains with valid HTTPS, zero suspicious TLDs, and clean structural ratios. The HTML form action points directly to Google/Microsoft servers.
2. **Confirmation Status:** **CONFIRMED ARCHITECTURALLY**.
3. **Practical Impact:**  
   The ML classifier will classify the page as **SAFE (Low Risk)** because all 43 structural features align with legitimate cloud software.
4. **How encountered:** Highly common in modern credential harvesting campaigns targeting enterprise workers.
5. **Realistic Mitigation:**  
   Implement brand impersonation detection (analyzing form field placeholders for keywords like "Password" on generic hosting platforms) and logo perceptual hashing.
6. **Priority:** **CRITICAL (P1)**

---

### False Negative 2: Client-Side Obfuscated & Delayed-Render Phishing Kits
- **Attack Scenario:** Attackers deliver a blank HTML page that decrypts and injects a fake Microsoft/Google login form via JavaScript after 500 ms.
1. **Why it exists:**  
   PhishGuard uses static `requests.get()`. It does not execute JavaScript. The parser sees no forms, no password fields, and no external form actions.
2. **Confirmation Status:** **CONFIRMED ARCHITECTURALLY**.
3. **Practical Impact:**  
   The system triggers degraded mode, dampens the risk score to `<= 48%` (or even Safe if the URL is clean), and allows the user to interact with the decrypted phishing form without a high-risk warning.
4. **How encountered:** Standard evasive phishing kits (e.g. EvilProxy, Robin, Greatness).
5. **Realistic Mitigation:**  
   In-browser extension content script inspection (analyzing the live browser DOM directly from Chrome instead of re-fetching static HTML on the backend).
6. **Priority:** **HIGH (P2)**

---

### False Negative 3: Compromised Legitimate Websites with Phishing Sub-Pages
- **Attack Scenario:** Attacker exploits WordPress on a high-reputation domain and uploads a phishing lure at `https://legitimate-bakery.com/wp-content/themes/login.html`.
1. **Why it exists:**  
   The bakery website has hundreds of legitimate internal navigation links (`num_links > 50`, `num_internal_links > 40`). Because link counts dominate 43% of the XGBoost split decisions, the high link count overwhelmingly pulls the model output toward the **Benign** class!
2. **Confirmation Status:** **CONFIRMED** via feature importance analysis ([05_MACHINE_LEARNING_AND_DATASET_AUDIT.md](file:///c:/Users/Udhaya/S5_Phishing_Detector/PROJECT_AUDIT_REPORT/05_MACHINE_LEARNING_AND_DATASET_AUDIT.md)).
3. **Practical Impact:**  
   Compromised legitimate domains easily evade detection.
4. **How encountered:** Extremely common enterprise threat.
5. **Realistic Mitigation:**  
   De-couple link count from classification by capping raw counts or using localized link-density ratios relative to form positioning.
6. **Priority:** **HIGH (P2)**

---

## 3. Operational & Browser Security Limitations

| Operational Limitation | Root Cause | Failure Mode | Mitigation |
| :--- | :--- | :--- | :--- |
| **Fail-Open on Backend Outage** | Extension cannot evaluate URLs locally; backend offline returns fetch error. | Extension shows red error icon; page continues to run without any warning or protection. | Local client-side lightweight rule engine in extension for offline mode. |
| **No In-Flight Protection** | Extension has no `webNavigation` or `declarativeNetRequest` listener. | Malicious scripts execute, steal credentials, and transmit data before user opens popup. | Upgrade extension to intercept navigation events prior to `DOMContentLoaded`. |
| **Network Latency Spike** | Synchronous `socket.getaddrinfo()` and `requests.get()` block on slow targets. | Backend response takes 8–10 seconds, exceeding client timeout. | Enforce strict 2.5-second DNS/socket deadlines via non-blocking async clients. |
