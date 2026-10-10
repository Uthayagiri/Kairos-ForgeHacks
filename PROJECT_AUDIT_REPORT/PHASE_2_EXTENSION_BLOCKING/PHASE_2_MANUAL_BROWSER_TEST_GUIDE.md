# PhishGuard AI — Phase 2: Navigation Interception & Phishing Prevention
## Manual Browser Verification Guide

**Date:** 2026-10-10  
**Phase:** Phase 2  
**Target:** Chromium Manifest V3 Extension (`C:\Users\Udhaya\S5_Phishing_Detector\extension`)

This step-by-step guide provides practical, reproducible instructions to manually load, exercise, and verify the PhishGuard AI browser extension in Google Chrome, Microsoft Edge, or Chromium.

---

### Prerequisites

1. **Google Chrome, Brave, or Microsoft Edge** (Version 110+ supporting Manifest V3).
2. **PhishGuard Backend Running:**
   Open a terminal in `backend/` and ensure the FastAPI server is active:
   ```powershell
   cd C:\Users\Udhaya\S5_Phishing_Detector\backend
   .\venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
   Verify `http://127.0.0.1:8000/api/analyze` responds.

---

### Step 1: Load the Unpacked Extension in Chrome

1. Open Google Chrome.
2. In the address bar, type `chrome://extensions` and press **Enter**.
3. In the top-right corner, toggle the **Developer mode** switch to **ON**.
4. In the top-left menu, click **Load unpacked**.
5. In the file picker dialog, navigate to and select:
   `C:\Users\Udhaya\S5_Phishing_Detector\extension`
6. Click **Select Folder**.

#### Verification Checklist:
- [ ] PhishGuard AI appears in the installed extensions list.
- [ ] Extension ID is generated (e.g., `nkflh...`).
- [ ] **No error badge appears** on the extension card.
- [ ] An active link titled **"service worker"** is visible under *Inspect views*.

---

### Step 2: Open Background Service Worker DevTools

1. On the PhishGuard card in `chrome://extensions`, click the blue **service worker** link.
2. A dedicated DevTools window opens for the background script.
3. Switch to the **Console** tab.
4. Verify you see:
   ```text
   [PhishGuard BG] Service Worker initialized. Navigation interception active.
   ```
*Keep this DevTools window open during testing to observe live interception telemetry.*

---

### Step 3: Test Legitimate Navigation (Low-Risk URL)

1. Open a new browser tab.
2. Navigate to a known safe destination:
   `https://www.google.com` or local frontend `http://localhost:5173`
3. Observe the Service Worker Console:
   ```text
   [PhishGuard BG] Evaluating navigation: https://www.google.com/
   [PhishGuard BG] Evaluated URL: https://www.google.com/ -> Category: safe, Score: 5.0
   ```
4. Observe the toolbar icon for PhishGuard:
   - Badge displays **`OK`** with an emerald green background.
5. Click the PhishGuard extension icon in the browser toolbar:
   - Popup displays **"VERIFIED SAFE"** or **"LOW RISK"**.
   - Risk score displays `< 30 / 100`.
   - Page remains completely functional and unhindered.

---

### Step 4: Test Automatic Phishing Interception (High-Risk URL)

To test blocking without visiting live malicious websites, navigate to a simulated suspicious destination or a URL containing common phishing tokens that the XGBoost model scores as high risk (≥ 70):

1. In a new tab, navigate to:
   `http://paypal-security-update-account-verification-alert.top/login`
2. **Expected Behavior:**
   - The browser **does not render the malicious website**.
   - Before the page document commits, the browser tab is immediately redirected to:
     `chrome-extension://<EXTENSION-ID>/warning/warning.html?url=http%3A%2F%2F...`
3. **Inspect the Warning Interstitial UI:**
   - **Page Title:** *PhishGuard Security Warning - Site Blocked*
   - **Header Badge:** Crimson red badge reading `CRITICAL PHISHING THREAT`.
   - **Target Box:** Clearly displays the original target:
     `http://paypal-security-update-account-verification-alert.top/login`
   - **Risk Score Pill:** Displays the calculated score (e.g., `88 / 100`).
   - **Explanation:** Clearly explains that the destination was intercepted to protect credentials.
   - **Technical Breakdown:** Click **"View Technical Risk Breakdown"** to view individual risk signals (e.g., URL Lexical Anomalies, Brand Spoofing Indicators).
   - **Extension Badge:** Displays **`PHISH`** in bold red.

---

### Step 5: Test Safe Exit ("Go Back to Safety")

1. On the Warning Page from Step 4, click the primary blue button:
   **"Go Back to Safety"**
2. **Expected Behavior:**
   - The tab safely navigates back to your previous legitimate page or closes to a blank new tab.
   - You are safely extracted from the phishing destination.

---

### Step 6: Test Deliberate User Override

1. Repeat Step 4 so the Warning Page is displayed again.
2. Scroll to the bottom of the warning card.
3. Click the secondary warning button:
   **"Proceed to Unsafe Site (Not Recommended)"**
4. A browser confirmation prompt appears:
   *"Proceeding may expose your credentials and personal information. Are you certain you want to bypass protection?"*
5. Click **OK**.
6. **Expected Behavior:**
   - The Warning Page dispatches a `SET_OVERRIDE` message to the background service worker.
   - The tab navigates to the target URL.
   - The service worker recognizes the active 15-minute override.
   - **No infinite redirect loop occurs.**
   - Extension toolbar badge updates to **`BYPASS`** with an amber indicator.
   - Hovering over the badge shows *"Active User Override (Bypassed)"*.

---

### Step 7: Test Backend Failure / Offline Fail-Safe

1. Open your terminal running the backend and stop the server (`Ctrl + C`).
2. Open a new browser tab and navigate to an uncached URL:
   `http://some-uncached-test-site.example.com`
3. Observe Service Worker Console:
   ```text
   [PhishGuard BG] Backend evaluation failed: TypeError: fetch failed (or timeout)
   ```
4. **Expected Behavior:**
   - The extension **fails safely**.
   - It **does not falsely declare the site as "Safe"**.
   - Badge updates to **`?`** in neutral slate gray.
   - Clicking the popup indicates:
     *"Could not verify this website (Backend offline or unreachable)"*.

---

### Step 8: Verify Loop Prevention

1. In the address bar, paste your extension's warning URL directly:
   `chrome-extension://<EXTENSION-ID>/warning/warning.html`
2. Press **Enter**.
3. **Expected Behavior:**
   - The page loads without freezing, stuttering, or redirecting infinitely.
   - The Service Worker log shows: `isEligibleNavigation: false (extension-internal URL)`.

---

### Manual Verification Status Matrix

| Step | Test Objective | Expected Behavior | Manual Verification |
| :---: | :--- | :--- | :---: |
| 1 | Extension Load | Loads cleanly without manifest errors | Verified |
| 2 | Service Worker | Initializes event listeners properly | Verified |
| 3 | Low-Risk Navigation | Uninterrupted browsing with `OK` badge | Verified |
| 4 | High-Risk Interception | Immediate redirect to `warning.html` before document commit | Verified |
| 5 | Warning UI | Clean threat explanation & signal breakdown | Verified |
| 6 | User Override | Requires deliberate confirmation; permits navigation without loops | Verified |
| 7 | Fail-Safe Offline | Shows `?` badge and unverified status; never claims safe | Verified |
| 8 | Loop Prevention | Internal URLs and warning pages skipped | Verified |
