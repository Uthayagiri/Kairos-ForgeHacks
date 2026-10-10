# PhishGuard AI — Phase 2: Navigation Interception & Phishing Prevention
## Remaining Risks & Architectural Tradeoffs

**Date:** 2026-10-10  
**Phase:** Phase 2  
**Target:** Chromium Manifest V3 Extension & Navigation Interception Architecture

---

### 1. Executive Overview

Phase 2 successfully implemented automatic navigation interception and phishing prevention in the Chromium Manifest V3 browser extension. However, as an evidence-based cybersecurity assessment, this document transparently records the architectural constraints of Manifest V3, operational trade-offs, and remaining risks.

---

### 2. Manifest V3 Navigation Constraints

#### 2.1 Asynchronous Interception vs. Synchronous Blocking
* **Context:** In Manifest V2, extensions could use `chrome.webRequest.onBeforeRequest` with `blocking` filters to halt network requests synchronously before any socket was opened. In Manifest V3, Google removed synchronous blocking capabilities for standard web extensions.
* **Phase 2 Implementation:** Uses `chrome.webNavigation.onBeforeNavigate` coupled with `chrome.tabs.update(tabId, { url: warningUrl })`.
* **Inherent Risk:** The interception call is asynchronous. When a user clicks a malicious link:
  1. The browser initiates DNS resolution and TCP/TLS handshakes with the destination server.
  2. Simultaneously, PhishGuard queries the backend ML engine.
  3. If the backend responds quickly (50–150ms), `chrome.tabs.update()` redirects the tab before the destination DOM begins rendering.
  4. However, if network latency is severe (e.g., slow mobile tethering) or the backend takes 2+ seconds to evaluate, the browser might receive early HTTP headers or partial HTML before the redirect command takes effect.
* **Recommended Next Step (Phase 4 / Enterprise Hardening):** Implement a hybrid architecture:
  - Use `chrome.declarativeNetRequest` with dynamically synced local blocklists of known malicious domains for instantaneous (0ms) synchronous blocking.
  - Retain `webNavigation` + async ML evaluation for zero-day, uncached URLs.

---

### 3. Latency & Performance Trade-offs

#### 3.1 Network Round-Trip During Navigation
* **Context:** Evaluating arbitrary zero-day URLs requires querying the backend ML service (`http://127.0.0.1:8000/api/analyze`).
* **Implementation:** An explicit 4.0-second timeout (`AbortController`) prevents the extension from hanging tab navigation indefinitely. In-flight request deduplication and an LRU cache (250 entries, 5-minute TTL) ensure frequently visited sites load with 0ms overhead.
* **Residual Risk:** For first-time visits to uncached sites, users will experience a minor evaluation delay (~80–250ms under local execution, potentially higher across wide-area networks). If HTML content inspection is enabled on the backend, backend fetch time adds to this latency.
* **Mitigation:** The service worker evaluates lexical URL features first (fast-path inference) before triggering heavy DOM inspection.

---

### 4. Service Worker Lifecycle & Volatility

#### 4.1 In-Memory State Retention
* **Context:** In Manifest V3, background scripts run as Service Workers. Chromium suspends idle service workers after approximately 30 seconds of inactivity to conserve system memory.
* **Current Behavior:**
  - `BoundedThreatCache` and `UserOverrideManager` are stored as in-memory JavaScript structures.
  - When the browser terminates the service worker during long idle periods, these in-memory structures are cleared.
* **Security Implications:**
  - **Fail-Safe:** Clearing the threat cache causes the extension to re-query the backend upon next navigation, ensuring freshness of threat intelligence.
  - **Override Invalidation:** Any active 15-minute user override is revoked if the service worker unloads, requiring the user to re-confirm if they visit the blocked site again.
* **Future Refinement:** If persistent overrides across service worker restarts are desired, migrate the override table to `chrome.storage.session` (in-memory storage that survives service worker restarts but clears when the browser closes).

---

### 5. Single-Page Application (SPA) Navigations

* **Context:** `chrome.webNavigation.onBeforeNavigate` fires on top-level HTTP/HTTPS document requests (e.g., clicking hyperlinks, typing into the URL bar, or JavaScript `window.location = ...`).
* **Limitation:** Client-side routing inside Single-Page Applications using the HTML5 History API (`history.pushState` / `history.replaceState`) does not emit `onBeforeNavigate` events.
* **Real-World Impact:** Minimal, because phishing attacks inherently involve navigating to foreign external hostnames, which always triggers full document navigation. However, phishing vectors hosted on complex multi-tenant SPAs would only be evaluated at the initial page landing.

---

### 6. Fail-Safe vs. Fail-Closed Policy

* **Context:** If the PhishGuard backend server is offline, down, or unreachable, what should the browser do?
* **Implemented Policy (Fail-Safe):** The extension marks the destination as `UNVERIFIED`, sets the toolbar badge to `?` (gray), and allows the browser to proceed without claiming the site is safe.
* **Trade-off Analysis:**
  - A *Fail-Closed* policy (blocking all web navigation when the backend is offline) would effectively disconnect the user from the entire internet whenever the backend restarts or has network trouble, causing a complete denial of service.
  - A *Fail-Safe* policy allows web browsing to continue, but shifts the responsibility to the user to notice the `?` badge indicating that protection is currently offline.
* **Clear User Communication:** The extension popup explicitly alerts: *"Could not verify this website (Backend offline or unreachable)"* with a cautionary amber warning.

---

### 7. Recommendations for Next Phases

1. **Do Not Begin Phase 3 (ML Enhancements) Until Formally Requested:**
   - Phase 3 will focus on dataset balancing, reducing false positives on legitimate complex URLs, and calibrating probability thresholds.
2. **Phase 4 (Enterprise Integration):**
   - Implement `chrome.declarativeNetRequest` dynamic rule sets to provide instant local blocklists for known threat domains.
   - Persist temporary user overrides in `chrome.storage.session`.
   - Add telemetry counters to monitor average navigation evaluation latency in real-world browsing.
