/**
 * Comprehensive verification script for PhishGuard AI Chrome Extension (Stage 11)
 * 1. Validates manifest.json against Chrome Manifest V3 schema
 * 2. Validates icons and background service worker existence & binary headers
 * 3. Validates popup.html and popup.css integrity
 * 4. Runs popup.js core logic in Node with mocked Chrome APIs & DOM
 * 5. Tests end-to-end live API communication with Stage 9 FastAPI backend
 */

const fs = require('fs');
const path = require('path');
const http = require('http');

const EXTENSION_DIR = path.resolve(__dirname, '..', 'extension');
let totalTests = 0;
let passedTests = 0;

function assert(condition, message) {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`  \x1b[32m✔ PASS\x1b[0m: ${message}`);
  } else {
    console.error(`  \x1b[31m✖ FAIL\x1b[0m: ${message}`);
    throw new Error(`Assertion failed: ${message}`);
  }
}

// -------------------------------------------------------------
// Test 1: Manifest V3 Schema & Configuration Validation
// -------------------------------------------------------------
console.log('\n========================================');
console.log('1. VALIDATING MANIFEST.JSON (MANIFEST V3)');
console.log('========================================');

const manifestPath = path.join(EXTENSION_DIR, 'manifest.json');
assert(fs.existsSync(manifestPath), 'manifest.json file exists');

const manifestRaw = fs.readFileSync(manifestPath, 'utf8');
let manifest;
try {
  manifest = JSON.parse(manifestRaw);
  assert(true, 'manifest.json is valid JSON');
} catch (e) {
  assert(false, `manifest.json JSON parse error: ${e.message}`);
}

assert(manifest.manifest_version === 3, 'manifest_version is exactly 3');
assert(typeof manifest.name === 'string' && manifest.name.length > 0, `Extension name is present: "${manifest.name}"`);
assert(typeof manifest.version === 'string' && /^\d+\.\d+\.\d+$/.test(manifest.version), `Version format is valid semver: "${manifest.version}"`);
assert(typeof manifest.description === 'string' && manifest.description.length > 0, `Description is present`);

// Action (Popup) validation
assert(typeof manifest.action === 'object', 'action object is defined');
assert(manifest.action.default_popup === 'popup/popup.html', 'action.default_popup points to "popup/popup.html"');
assert(fs.existsSync(path.join(EXTENSION_DIR, manifest.action.default_popup)), 'popup/popup.html exists on disk');

// Background service worker validation
assert(typeof manifest.background === 'object', 'background object is defined');
assert(manifest.background.service_worker === 'background/service-worker.js', 'background.service_worker points to "background/service-worker.js"');
assert(fs.existsSync(path.join(EXTENSION_DIR, manifest.background.service_worker)), 'background/service-worker.js exists on disk');

// Icons validation
assert(typeof manifest.icons === 'object', 'icons object is defined');
['16', '48', '128'].forEach((size) => {
  const iconRel = manifest.icons[size];
  assert(Boolean(iconRel), `Icon size ${size} is defined in manifest.icons: ${iconRel}`);
  const iconAbs = path.join(EXTENSION_DIR, iconRel);
  assert(fs.existsSync(iconAbs), `Icon file ${iconRel} exists on disk`);
  const stats = fs.statSync(iconAbs);
  assert(stats.size > 50, `Icon file ${iconRel} is non-empty (${stats.size} bytes)`);

  // Verify PNG signature (89 50 4E 47 0D 0A 1A 0A)
  const header = fs.readFileSync(iconAbs).slice(0, 8);
  const isPng = header.toString('hex') === '89504e470d0a1a0a';
  assert(isPng, `Icon ${iconRel} has valid PNG signature`);
});

// Permissions validation
assert(Array.isArray(manifest.permissions), 'permissions is an array');
assert(manifest.permissions.includes('activeTab'), 'permissions includes "activeTab"');
assert(
  manifest.permissions.length === 1 && manifest.permissions[0] === 'activeTab',
  'permissions follows least-privilege (strictly ["activeTab"])'
);

assert(Array.isArray(manifest.host_permissions), 'host_permissions is an array');
assert(
  manifest.host_permissions.some(p => p.includes('127.0.0.1:8000')),
  'host_permissions allows communication with 127.0.0.1:8000'
);

// -------------------------------------------------------------
// Test 2: Background Service Worker Validation
// -------------------------------------------------------------
console.log('\n========================================');
console.log('2. VALIDATING BACKGROUND SERVICE WORKER');
console.log('========================================');

const workerPath = path.join(EXTENSION_DIR, 'background', 'service-worker.js');
const workerContent = fs.readFileSync(workerPath, 'utf8');
assert(workerContent.includes('chrome.runtime.onInstalled'), 'service-worker registers chrome.runtime.onInstalled listener');
assert(!workerContent.includes('localStorage'), 'service-worker does not violate MV3 worker restrictions (no localStorage)');

// -------------------------------------------------------------
// Test 3: Popup HTML & CSS Integrity
// -------------------------------------------------------------
console.log('\n========================================');
console.log('3. VALIDATING POPUP HTML & CSS INTEGRITY');
console.log('========================================');

const popupHtmlPath = path.join(EXTENSION_DIR, 'popup', 'popup.html');
const popupHtml = fs.readFileSync(popupHtmlPath, 'utf8');

const requiredElements = [
  'popup-container',
  'target-url-text',
  'manual-input-panel',
  'manual-url-input',
  'manual-scan-btn',
  'loading-view',
  'result-view',
  'unanalyzable-view',
  'error-view',
  'verdict-banner',
  'verdict-icon-wrap',
  'verdict-title',
  'verdict-subtitle',
  'gauge-fill',
  'degraded-notice',
  'spa-notice',
  'indicators-container',
  'signals-grid',
  'exec-time-text',
  'rescan-tab-btn',
];

requiredElements.forEach((idOrClass) => {
  assert(popupHtml.includes(idOrClass), `popup.html contains required element/class "${idOrClass}"`);
});

const popupCssPath = path.join(EXTENSION_DIR, 'popup', 'popup.css');
assert(fs.existsSync(popupCssPath), 'popup.css exists on disk');
const popupCss = fs.readFileSync(popupCssPath, 'utf8');
assert(popupCss.includes('safe-banner') && popupCss.includes('phishing-banner'), 'popup.css contains verdict styling tokens');
assert(popupCss.includes('badge-danger') && popupCss.includes('badge-warning'), 'popup.css contains badge severity styles');

// -------------------------------------------------------------
// Test 4: Popup JS Core Logic Unit & Mock DOM Tests
// -------------------------------------------------------------
console.log('\n========================================');
console.log('4. TESTING POPUP.JS CORE LOGIC & TAXONOMY');
console.log('========================================');

// Create a lightweight DOM simulation
class MockClassList {
  constructor() {
    this.classes = new Set();
  }
  add(...names) { names.forEach(n => this.classes.add(n)); }
  remove(...names) { names.forEach(n => this.classes.delete(n)); }
  toggle(name) {
    if (this.classes.has(name)) {
      this.classes.delete(name);
      return false;
    } else {
      this.classes.add(name);
      return true;
    }
  }
  contains(name) { return this.classes.has(name); }
}

class MockElement {
  constructor(tagName = 'div', id = '') {
    this.tagName = tagName.toUpperCase();
    this.id = id;
    this.classList = new MockClassList();
    this.children = [];
    this.textContent = '';
    this.innerHTML = '';
    this.attributes = {};
    this.style = {};
  }
  setAttribute(k, v) { this.attributes[k] = v; }
  getAttribute(k) { return this.attributes[k]; }
  appendChild(child) {
    this.children.push(child);
    return child;
  }
  get className() { return Array.from(this.classList.classes).join(' '); }
  set className(val) {
    this.classList.classes.clear();
    if (val) val.split(/\s+/).filter(Boolean).forEach(c => this.classList.add(c));
  }
}

const mockDomElements = {};
[
  'loading-view', 'result-view', 'unanalyzable-view', 'error-view',
  'target-url-text', 'manual-input-panel', 'manual-url-input',
  'manual-scan-btn', 'rescan-tab-btn', 'error-retry-btn',
  'unanalyzable-manual-btn', 'loading-sub-text',
  'verdict-banner', 'verdict-icon-wrap', 'verdict-title',
  'verdict-subtitle', 'gauge-fill', 'degraded-notice', 'spa-notice',
  'indicators-container', 'signals-grid', 'exec-time-text',
  'error-title', 'error-desc', 'unanalyzable-desc'
].forEach(id => {
  mockDomElements[id] = new MockElement('div', id);
});

global.document = {
  getElementById: (id) => mockDomElements[id] || null,
  createElement: (tag) => new MockElement(tag),
  querySelectorAll: () => [],
  addEventListener: () => {},
};

// Mock Chrome API
global.chrome = {
  tabs: {
    query: async (queryInfo) => {
      return [{ id: 1, url: 'https://en.wikipedia.org/wiki/Main_Page' }];
    },
  },
};

// Load popup.js module
const popupModule = require(path.join(EXTENSION_DIR, 'popup', 'popup.js'));
const {
  checkUrlAnalyzable,
  getIndicatorSeverity,
  renderResult,
  showView,
  setTargetUrlDisplay,
  getActiveTabUrl,
} = popupModule;

// Test 4.1: URL Analyzability check
console.log('--- Testing checkUrlAnalyzable() ---');
assert(checkUrlAnalyzable('https://google.com').analyzable === true, 'https://google.com is analyzable');
assert(checkUrlAnalyzable('http://192.168.1.1/login.php').analyzable === true, 'http://192.168.1.1/login.php is analyzable');
assert(checkUrlAnalyzable('chrome://extensions').analyzable === false, 'chrome://extensions is detected as unanalyzable');
assert(checkUrlAnalyzable('about:blank').analyzable === false, 'about:blank is detected as unanalyzable');
assert(checkUrlAnalyzable('file:///C:/test.html').analyzable === false, 'file:/// path is detected as unanalyzable');
assert(checkUrlAnalyzable('').analyzable === false, 'Empty string is detected as unanalyzable');

// Test 4.2: Indicator Severity Mapping
console.log('--- Testing getIndicatorSeverity() ---');
const httpsMissingSev = getIndicatorSeverity('Connection does not use secure HTTPS encryption');
assert(
  httpsMissingSev.badgeClass === 'badge-warning' && httpsMissingSev.label === 'Warning',
  'Missing HTTPS correctly mapped to Warning (not Positive/Safe!)'
);

const keywordsSev = getIndicatorSeverity('URL contains sensitive or authentication-related keywords');
assert(
  keywordsSev.badgeClass === 'badge-warning' && keywordsSev.label === 'Warning',
  'Sensitive keywords correctly mapped to Warning (not neutral Info)'
);

const rawIpSev = getIndicatorSeverity('URL hostname is a raw IPv4 address');
assert(
  rawIpSev.badgeClass === 'badge-danger' && rawIpSev.label === 'High Threat',
  'Raw IP hostname correctly mapped to High Threat / badge-danger'
);

const safeSslSev = getIndicatorSeverity('Valid SSL certificate and secure connection');
assert(
  safeSslSev.badgeClass === 'badge-safe' && safeSslSev.label === 'Positive',
  'Valid SSL certificate correctly mapped to Positive / badge-safe'
);

// Test 4.3: View Switcher
console.log('--- Testing showView() ---');
showView('loading');
assert(!mockDomElements['loading-view'].classList.contains('hidden'), 'loading-view is visible');
assert(mockDomElements['result-view'].classList.contains('hidden'), 'result-view is hidden');

showView('result');
assert(mockDomElements['loading-view'].classList.contains('hidden'), 'loading-view is hidden');
assert(!mockDomElements['result-view'].classList.contains('hidden'), 'result-view is visible');

// Test 4.4: renderResult() Safe payload
console.log('--- Testing renderResult() with Safe Verdict ---');
renderResult({
  url: 'https://example.com',
  status: 'safe',
  risk_level: 'low',
  confidence_score: 0.05,
  html_available: true,
  indicators: ['Valid SSL connection'],
  extracted_features: { domain_length: 11 },
  execution_time_ms: 12.4,
});

assert(mockDomElements['verdict-banner'].classList.contains('safe-banner'), 'Verdict banner has safe-banner class');
assert(mockDomElements['verdict-title'].textContent === 'Legitimate / Safe', 'Verdict title is "Legitimate / Safe"');
assert(mockDomElements['gauge-fill'].classList.contains('safe-fill'), 'Gauge fill has safe-fill class');
assert(mockDomElements['degraded-notice'].classList.contains('hidden'), 'Degraded notice is hidden when html_available=true');
assert(mockDomElements['indicators-container'].children.length === 1, '1 indicator rendered in container');

// Test 4.5: renderResult() Degraded / Suspicious payload
console.log('--- Testing renderResult() with Degraded / Suspicious Verdict ---');
renderResult({
  url: 'http://unreachable-test-site.org',
  status: 'suspicious',
  risk_level: 'medium',
  confidence_score: 0.55,
  html_available: false,
  indicators: ['HTML unreachable - analysis based on URL structure only', 'Connection does not use secure HTTPS encryption'],
  extracted_features: { domain_length: 26 },
  execution_time_ms: 5020.1,
});

assert(mockDomElements['verdict-banner'].classList.contains('suspicious-banner'), 'Verdict banner has suspicious-banner class');
assert(mockDomElements['verdict-title'].textContent === 'Suspicious / Caution', 'Verdict title is "Suspicious / Caution"');
assert(!mockDomElements['degraded-notice'].classList.contains('hidden'), 'Degraded notice is VISIBLE when html_available=false');

// Test 4.5b: renderResult() SPA Client-Side Rendered payload
console.log('--- Testing renderResult() with SPA Client-Side Rendered Payload ---');
renderResult({
  url: 'https://ps.bitsathy.ac.in',
  status: 'suspicious',
  risk_level: 'medium',
  confidence_score: 0.45,
  html_available: true,
  content_rendering_incomplete: true,
  indicators: ['Page appears to be a JavaScript-rendered application'],
  extracted_features: { domain_length: 17 },
  execution_time_ms: 700.0,
});

assert(mockDomElements['degraded-notice'].classList.contains('hidden'), 'Degraded notice is hidden when html_available=true');
assert(!mockDomElements['spa-notice'].classList.contains('hidden'), 'SPA notice is VISIBLE when content_rendering_incomplete=true');

// Test 4.6: renderResult() Phishing Threat payload
console.log('--- Testing renderResult() with Phishing Verdict ---');
renderResult({
  url: 'http://192.168.1.100/paypal/login.php',
  status: 'phishing',
  risk_level: 'high',
  confidence_score: 0.96,
  html_available: false,
  indicators: ['URL hostname is a raw IPv4 address', 'URL contains sensitive or authentication-related keywords'],
  extracted_features: { domain_length: 13 },
  execution_time_ms: 45.0,
});

assert(mockDomElements['verdict-banner'].classList.contains('phishing-banner'), 'Verdict banner has phishing-banner class');
assert(mockDomElements['verdict-title'].textContent === 'Phishing Threat Detected', 'Verdict title is "Phishing Threat Detected"');

// Test 4.7: Mock Chrome activeTab URL
console.log('--- Testing getActiveTabUrl() ---');
getActiveTabUrl().then(async (tabUrl) => {
  assert(tabUrl === 'https://en.wikipedia.org/wiki/Main_Page', 'getActiveTabUrl returns active tab URL from chrome.tabs.query');

  // -------------------------------------------------------------
  // Test 5: Live FastAPI Backend Communication Test
  // -------------------------------------------------------------
  console.log('\n========================================');
  console.log('5. TESTING LIVE FASTAPI BACKEND (POST /predict)');
  console.log('========================================');

  try {
    const safeRes = await popupModule.fetchPrediction('https://example.com');
    assert(safeRes.status === 'safe', `Live POST /predict https://example.com -> status: ${safeRes.status}`);
    const safeConfidence = typeof safeRes.confidence === 'number' ? safeRes.confidence : safeRes.confidence_score;
    assert(typeof safeConfidence === 'number', `Live confidence score: ${safeConfidence}`);
    assert(safeRes.risk_level === 'low', `Live risk_level: ${safeRes.risk_level}`);

    const phishRes = await popupModule.fetchPrediction('http://192.168.1.100/paypal/login.php');
    assert(phishRes.status === 'phishing', `Live POST /predict raw IP phish -> status: ${phishRes.status}`);
    assert(phishRes.risk_level === 'high', `Live risk_level: ${phishRes.risk_level}`);

    console.log('\n========================================');
    console.log(`ALL ${passedTests}/${totalTests} TESTS PASSED SUCCESSFULLY! 🚀`);
    console.log('========================================\n');
  } catch (err) {
    console.error('FastAPI test error:', err);
    process.exit(1);
  }
});
