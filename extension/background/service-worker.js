/**
 * PhishGuard AI Background Service Worker (Manifest V3)
 *
 * Implements real-time top-level navigation interception, automated phishing blocking,
 * bounded LRU threat caching, in-flight request deduplication, safe user overrides,
 * and tab badge security telemetry.
 */

// -----------------------------------------------------------------------------
// 1. Configuration & Documented Risk Thresholds
// -----------------------------------------------------------------------------

const CONFIG = {
  API_BASE_URL: 'http://127.0.0.1:8000',
  AUTO_INTERCEPT: true,
  FETCH_TIMEOUT_MS: 4000,          // 4-second defensive navigation timeout
  CACHE_MAX_ENTRIES: 250,          // Bounded cache capacity
  CACHE_TTL_MS: 5 * 60 * 1000,     // 5-minute cache TTL for verified verdicts
  ERROR_CACHE_TTL_MS: 15 * 1000,   // 15-second short TTL for network errors / offline backend
  OVERRIDE_TTL_MS: 15 * 60 * 1000, // 15-minute user override grace period
};

// Documented Risk Policy Thresholds (matching backend risk_scoring.py)
const RISK_THRESHOLDS = {
  LOW: 30,   // Risk Score < 30   -> 'low' / 'safe'
  HIGH: 70,  // Risk Score >= 70  -> 'high' / 'phishing' (Interception Trigger)
};

// -----------------------------------------------------------------------------
// 2. Bounded LRU Threat Cache
// -----------------------------------------------------------------------------

class BoundedThreatCache {
  constructor(maxEntries = CONFIG.CACHE_MAX_ENTRIES, defaultTtlMs = CONFIG.CACHE_TTL_MS) {
    this.maxEntries = maxEntries;
    this.defaultTtlMs = defaultTtlMs;
    this.cache = new Map(); // Preserves insertion/access order
  }

  _normalizeKey(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return '';
    try {
      const parsed = new URL(rawUrl.trim());
      // Strip trailing slashes and hash fragments for consistent lookup
      return `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/+$/, '')}${parsed.search}`;
    } catch {
      return rawUrl.trim().toLowerCase();
    }
  }

  get(rawUrl) {
    const key = this._normalizeKey(rawUrl);
    if (!key || !this.cache.has(key)) return null;

    const entry = this.cache.get(key);
    const now = Date.now();

    if (now > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    // Refresh LRU order (move to most recently accessed)
    this.cache.delete(key);
    this.cache.set(key, entry);
    return entry.data;
  }

  set(rawUrl, data, customTtlMs = null) {
    const key = this._normalizeKey(rawUrl);
    if (!key) return;

    const ttl = customTtlMs || this.defaultTtlMs;
    const expiresAt = Date.now() + ttl;

    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxEntries) {
      // Evict oldest entry (first item in Map)
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }

    this.cache.set(key, { data, expiresAt });
  }

  has(rawUrl) {
    return this.get(rawUrl) !== null;
  }

  clear() {
    this.cache.clear();
  }

  get size() {
    return this.cache.size;
  }
}

// -----------------------------------------------------------------------------
// 3. User Override Manager
// -----------------------------------------------------------------------------

class UserOverrideManager {
  constructor(defaultTtlMs = CONFIG.OVERRIDE_TTL_MS) {
    this.defaultTtlMs = defaultTtlMs;
    this.overrides = new Map(); // key -> expiresAt
  }

  _normalizeHostOrUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return '';
    try {
      const parsed = new URL(rawUrl.trim());
      return parsed.hostname.toLowerCase();
    } catch {
      return rawUrl.trim().toLowerCase();
    }
  }

  addOverride(rawUrl, customTtlMs = null) {
    const host = this._normalizeHostOrUrl(rawUrl);
    if (!host) return;
    const ttl = customTtlMs || this.defaultTtlMs;
    this.overrides.set(host, Date.now() + ttl);
    console.log(`[PhishGuard AI] User override registered for: ${host} (TTL: ${ttl / 1000}s)`);
  }

  hasOverride(rawUrl) {
    const host = this._normalizeHostOrUrl(rawUrl);
    if (!host || !this.overrides.has(host)) return false;

    const expiresAt = this.overrides.get(host);
    if (Date.now() > expiresAt) {
      this.overrides.delete(host);
      return false;
    }
    return true;
  }

  clear() {
    this.overrides.clear();
  }
}

// Global Singletons
const threatCache = new BoundedThreatCache();
const overrideManager = new UserOverrideManager();
const inFlightEvaluations = new Map(); // url -> Promise
const tabActiveNavigations = new Map(); // tabId -> { url, navId }

// -----------------------------------------------------------------------------
// 4. Backend Communication & Risk Evaluation
// -----------------------------------------------------------------------------

/**
 * Perform defensive URL evaluation against FastAPI backend
 */
async function evaluateUrlWithBackend(rawUrl) {
  // 1. Check Cache First
  const cached = threatCache.get(rawUrl);
  if (cached) {
    return cached;
  }

  // 2. Reuse In-Flight Request if already pending
  if (inFlightEvaluations.has(rawUrl)) {
    return inFlightEvaluations.get(rawUrl);
  }

  const evaluationPromise = (async () => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), CONFIG.FETCH_TIMEOUT_MS);

    try {
      // Primary endpoint: /api/analyze
      let response;
      try {
        response = await fetch(`${CONFIG.API_BASE_URL}/api/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({ url: rawUrl }),
          signal: controller.signal,
        });
      } catch (primaryErr) {
        // Fallback to /predict or /api/predict
        if (primaryErr.name !== 'AbortError') {
          response = await fetch(`${CONFIG.API_BASE_URL}/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify({ url: rawUrl }),
            signal: controller.signal,
          });
        } else {
          throw primaryErr;
        }
      }

      clearTimeout(timer);

      if (!response || !response.ok) {
        const errorResult = {
          url: rawUrl,
          status: 'error',
          risk_level: 'unknown',
          risk_score: 0,
          error_message: response ? `HTTP ${response.status}` : 'No response from server',
          verified: false,
        };
        threatCache.set(rawUrl, errorResult, CONFIG.ERROR_CACHE_TTL_MS);
        return errorResult;
      }

      const data = await response.json();

      // Normalize fields
      const riskScore = typeof data.risk_score === 'number'
        ? data.risk_score
        : (typeof data.confidence === 'number' ? Math.round(data.confidence * 100) : 0);

      let riskLevel = data.risk_level;
      if (!riskLevel) {
        if (riskScore >= RISK_THRESHOLDS.HIGH) riskLevel = 'high';
        else if (riskScore >= RISK_THRESHOLDS.LOW) riskLevel = 'medium';
        else riskLevel = 'low';
      }

      const normalizedResult = {
        url: data.url || rawUrl,
        status: data.status || (riskLevel === 'high' ? 'phishing' : riskLevel === 'medium' ? 'suspicious' : 'safe'),
        risk_level: riskLevel,
        risk_score: riskScore,
        confidence: data.confidence || (riskScore / 100),
        is_phishing: Boolean(data.is_phishing || riskLevel === 'high'),
        detected_indicators: Array.isArray(data.detected_indicators) ? data.detected_indicators : [],
        signals_breakdown: data.signals_breakdown || {},
        recommended_action: data.recommended_action || '',
        verified: true,
      };

      // Store in LRU cache
      threatCache.set(rawUrl, normalizedResult, CONFIG.CACHE_TTL_MS);
      return normalizedResult;

    } catch (err) {
      clearTimeout(timer);
      const isTimeout = err.name === 'AbortError';
      const failureResult = {
        url: rawUrl,
        status: 'error',
        risk_level: 'unknown',
        risk_score: 0,
        error_message: isTimeout ? 'Evaluation timed out' : (err.message || 'Backend connection failed'),
        verified: false,
      };

      // Cache failure briefly to prevent tight re-fetch loops while preserving fail-safe behavior
      threatCache.set(rawUrl, failureResult, CONFIG.ERROR_CACHE_TTL_MS);
      return failureResult;
    } finally {
      inFlightEvaluations.delete(rawUrl);
    }
  })();

  inFlightEvaluations.set(rawUrl, evaluationPromise);
  return evaluationPromise;
}

// -----------------------------------------------------------------------------
// 5. Navigation Interception Helpers
// -----------------------------------------------------------------------------

function isEligibleNavigation(details) {
  if (!details || details.frameId !== 0) return false;
  const url = details.url;
  if (!url || typeof url !== 'string') return false;

  const lower = url.trim().toLowerCase();
  // Only intercept web protocols
  if (!lower.startsWith('http://') && !lower.startsWith('https://')) {
    return false;
  }

  // NEVER intercept the extension's own pages (prevents warning loop!)
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL) {
    const extPrefix = chrome.runtime.getURL('').toLowerCase();
    if (lower.startsWith(extPrefix)) {
      return false;
    }
  }

  return true;
}

function buildWarningUrl(targetUrl, result) {
  const base = (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL)
    ? chrome.runtime.getURL('warning/warning.html')
    : 'warning/warning.html';

  const risk = encodeURIComponent(String(result?.risk_score ?? 85));
  const status = encodeURIComponent(result?.status || 'phishing');
  const reasons = encodeURIComponent(JSON.stringify(result?.detected_indicators || []));
  const signals = encodeURIComponent(JSON.stringify(result?.signals_breakdown || {}));

  return `${base}?url=${encodeURIComponent(targetUrl)}&risk=${risk}&status=${status}&reasons=${reasons}&signals=${signals}`;
}

function updateBadgeForTab(tabId, status, riskScore) {
  if (typeof chrome === 'undefined' || !chrome.action || !chrome.action.setBadgeText) return;

  try {
    if (status === 'phishing' || riskScore >= RISK_THRESHOLDS.HIGH) {
      chrome.action.setBadgeText({ text: 'PHISH', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId });
    } else if (status === 'suspicious' || (riskScore >= RISK_THRESHOLDS.LOW && riskScore < RISK_THRESHOLDS.HIGH)) {
      chrome.action.setBadgeText({ text: 'WARN', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId });
    } else if (status === 'safe') {
      chrome.action.setBadgeText({ text: 'OK', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId });
    } else if (status === 'override') {
      chrome.action.setBadgeText({ text: 'BYPASS', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#d97706', tabId });
    } else {
      chrome.action.setBadgeText({ text: '?', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#64748b', tabId });
    }
  } catch {
    // Ignore tab disposal errors
  }
}

// -----------------------------------------------------------------------------
// 6. Navigation Event Listener (Manifest V3 webNavigation)
// -----------------------------------------------------------------------------

async function handleBeforeNavigate(details) {
  if (!CONFIG.AUTO_INTERCEPT || !isEligibleNavigation(details)) {
    return;
  }

  const { tabId, url } = details;
  const navId = `${tabId}-${Date.now()}`;
  tabActiveNavigations.set(tabId, { url, navId });

  // 1. Check if destination has active user override
  if (overrideManager.hasOverride(url)) {
    console.log(`[PhishGuard AI] Navigation permitted via active user override: ${url}`);
    updateBadgeForTab(tabId, 'override', 0);
    return;
  }

  // 2. Synchronous Cache Check
  const cached = threatCache.get(url);
  if (cached) {
    if (cached.status === 'phishing' || cached.risk_score >= RISK_THRESHOLDS.HIGH) {
      console.warn(`[PhishGuard AI] Intercepting cached high-risk destination: ${url}`);
      updateBadgeForTab(tabId, 'phishing', cached.risk_score);
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.update) {
        chrome.tabs.update(tabId, { url: buildWarningUrl(url, cached) });
      }
      return;
    } else if (cached.status === 'suspicious') {
      updateBadgeForTab(tabId, 'suspicious', cached.risk_score);
      return;
    } else if (cached.status === 'safe') {
      updateBadgeForTab(tabId, 'safe', cached.risk_score);
      return;
    }
  }

  // 3. Asynchronous Live Evaluation
  try {
    const result = await evaluateUrlWithBackend(url);

    // Verify tab hasn't already navigated to another URL while waiting
    const currentTabNav = tabActiveNavigations.get(tabId);
    if (!currentTabNav || currentTabNav.navId !== navId) {
      return; // Discard stale navigation evaluation
    }

    // High Risk: Block navigation immediately and redirect to warning page
    if (result.status === 'phishing' || result.risk_score >= RISK_THRESHOLDS.HIGH) {
      console.warn(`[PhishGuard AI] High-risk phishing threat detected (${result.risk_score}%). Intercepting tab ${tabId} -> ${url}`);
      updateBadgeForTab(tabId, 'phishing', result.risk_score);

      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.update) {
        chrome.tabs.update(tabId, { url: buildWarningUrl(url, result) });
      }
    } else if (result.status === 'suspicious' || result.risk_score >= RISK_THRESHOLDS.LOW) {
      // Medium Risk: Allow navigation normally, present caution badge
      updateBadgeForTab(tabId, 'suspicious', result.risk_score);
    } else if (result.status === 'safe') {
      // Low Risk: Allow navigation normally
      updateBadgeForTab(tabId, 'safe', result.risk_score);
    } else {
      // Backend error / offline: Fail safely, do not falsely certify safe
      updateBadgeForTab(tabId, 'error', 0);
    }
  } catch (navErr) {
    console.error(`[PhishGuard AI] Navigation evaluation error for ${url}:`, navErr);
    updateBadgeForTab(tabId, 'error', 0);
  }
}

// Attach webNavigation listener if available
if (typeof chrome !== 'undefined' && chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
  chrome.webNavigation.onBeforeNavigate.addListener(handleBeforeNavigate);
  console.log('[PhishGuard AI] Navigation Interception Listener registered on chrome.webNavigation.');
}

// -----------------------------------------------------------------------------
// 7. Extension Lifecycle & Message Routing
// -----------------------------------------------------------------------------

if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onInstalled) {
  chrome.runtime.onInstalled.addListener((details) => {
    if (details.reason === 'install') {
      console.log('[PhishGuard AI] Extension installed. Initializing shield badge.');
      if (chrome.action && chrome.action.setBadgeText) {
        chrome.action.setBadgeText({ text: 'AI' });
        chrome.action.setBadgeBackgroundColor({ color: '#06b6d4' });
      }
    }
  });
}

// Handle messages from popup, warning page, or test harnesses
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (!request || !request.type) return false;

    switch (request.type) {
      case 'UPDATE_BADGE': {
        const tabId = request.tabId !== undefined ? request.tabId : (sender.tab ? sender.tab.id : undefined);
        updateBadgeForTab(tabId, request.status, request.score || 0);
        sendResponse({ success: true });
        break;
      }

      case 'GET_TAB_RISK': {
        const targetUrl = request.url;
        const cached = threatCache.get(targetUrl);
        sendResponse({ success: true, result: cached });
        break;
      }

      case 'SET_OVERRIDE': {
        if (request.url) {
          overrideManager.addOverride(request.url);
          sendResponse({ success: true, host: overrideManager._normalizeHostOrUrl(request.url) });
        } else {
          sendResponse({ success: false, error: 'Missing URL parameter' });
        }
        break;
      }

      case 'CLEAR_CACHE': {
        threatCache.clear();
        overrideManager.clear();
        sendResponse({ success: true, message: 'Cache and overrides cleared.' });
        break;
      }

      case 'EVALUATE_URL': {
        const tabId = request.tabId !== undefined ? request.tabId : (sender.tab ? sender.tab.id : undefined);
        evaluateUrlWithBackend(request.url)
          .then((result) => {
            if (tabId !== undefined) {
              updateBadgeForTab(tabId, result.status, result.risk_score);
            }
            sendResponse({ success: true, result });
          })
          .catch((err) => sendResponse({ success: false, error: err.message }));
        return true; // Keep message channel open for async response
      }

      case 'GET_CACHE_STATS': {
        sendResponse({
          success: true,
          cacheSize: threatCache.size,
          maxCapacity: threatCache.maxEntries,
        });
        break;
      }

      default:
        sendResponse({ success: false, error: `Unknown message type: ${request.type}` });
    }
    return true;
  });
}

// -----------------------------------------------------------------------------
// 8. Module Exports for Unit Testing & Automation (Node environment)
// -----------------------------------------------------------------------------

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    CONFIG,
    RISK_THRESHOLDS,
    BoundedThreatCache,
    UserOverrideManager,
    threatCache,
    overrideManager,
    inFlightEvaluations,
    tabActiveNavigations,
    evaluateUrlWithBackend,
    isEligibleNavigation,
    buildWarningUrl,
    handleBeforeNavigate,
    updateBadgeForTab,
  };
}
