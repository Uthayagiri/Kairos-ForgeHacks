/**
 * Full End-to-End Integration Verification Suite for Stage 12.
 * Validates all 8 Matrix items across Website & Chrome Extension pipelines.
 */

const http = require('http');
const path = require('path');
const fs = require('fs');

const EXTENSION_DIR = path.resolve(__dirname, '..', 'extension');
const FRONTEND_DIR = path.resolve(__dirname, '..', 'frontend');

// Mock DOM classes for popup and frontend simulation
class MockClassList {
  constructor() { this.classes = new Set(); }
  add(...names) { names.forEach(n => this.classes.add(n)); }
  remove(...names) { names.forEach(n => this.classes.delete(n)); }
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
  appendChild(child) { this.children.push(child); return child; }
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
].forEach(id => { mockDomElements[id] = new MockElement('div', id); });

global.document = {
  getElementById: (id) => mockDomElements[id] || null,
  createElement: (tag) => new MockElement(tag),
  querySelectorAll: () => [],
  addEventListener: () => {},
};

global.chrome = {
  tabs: {
    query: async () => [{ id: 1, url: 'https://en.wikipedia.org' }],
  },
};

const popupModule = require(path.join(EXTENSION_DIR, 'popup', 'popup.js'));

let testCount = 0;
let passCount = 0;

function check(title, condition, extra = '') {
  testCount++;
  if (condition) {
    passCount++;
    console.log(`  \x1b[32m✔ [PASS]\x1b[0m ${title} ${extra ? `(${extra})` : ''}`);
  } else {
    console.error(`  \x1b[31m✖ [FAIL]\x1b[0m ${title} ${extra ? `(${extra})` : ''}`);
    throw new Error(`Test failed: ${title}`);
  }
}

async function requestPost(url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(body);
    const u = new URL(url);
    const req = http.request({
      hostname: u.hostname,
      port: u.port,
      path: u.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        ...headers,
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, raw: data });
        }
      });
    });
    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

async function requestOptions(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({
      hostname: u.hostname,
      port: u.port,
      path: u.pathname,
      method: 'OPTIONS',
      headers: {
        ...headers,
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({ status: res.statusCode, headers: res.headers, data });
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function runMatrix() {
  console.log('\n============================================================');
  console.log('STAGE 12 INTEGRATION VERIFICATION SUITE');
  console.log('============================================================\n');

  const API_URL = 'http://127.0.0.1:8000/predict';

  // --- ITEM 1: SAFE URL END-TO-END ---
  console.log('--- MATRIX 1: SAFE URL END-TO-END (https://en.wikipedia.org) ---');
  const safeRes = await requestPost(API_URL, { url: 'https://en.wikipedia.org' });
  check('Safe URL returns HTTP 200', safeRes.status === 200);
  check('Safe URL verdict is safe', safeRes.body.status === 'safe');
  check('Safe URL risk_level is low', safeRes.body.risk_level === 'low');
  check('Safe URL is_phishing is false', safeRes.body.is_phishing === false);
  check('Safe URL confidence is low (<0.20)', safeRes.body.confidence < 0.20, `confidence = ${safeRes.body.confidence}`);
  check('Safe URL html_available is true', safeRes.body.html_available === true);

  // Render in extension popup logic
  popupModule.renderResult(safeRes.body);
  check('Extension renders safe-banner', mockDomElements['verdict-banner'].classList.contains('safe-banner'));
  check('Extension displays "Legitimate / Safe"', mockDomElements['verdict-title'].textContent === 'Legitimate / Safe');
  check('Extension hides degraded notice', mockDomElements['degraded-notice'].classList.contains('hidden'));

  // --- ITEM 2: PHISHING URL END-TO-END ---
  console.log('\n--- MATRIX 2: PHISHING URL END-TO-END (http://192.168.1.100/paypal/login.php) ---');
  const phishRes = await requestPost(API_URL, { url: 'http://192.168.1.100/paypal/login.php' });
  check('Phishing URL returns HTTP 200', phishRes.status === 200);
  check('Phishing URL verdict is phishing', phishRes.body.status === 'phishing');
  check('Phishing URL risk_level is high', phishRes.body.risk_level === 'high');
  check('Phishing URL is_phishing is true', phishRes.body.is_phishing === true);
  check('Phishing URL confidence is high (>0.80)', phishRes.body.confidence > 0.80, `confidence = ${phishRes.body.confidence}`);
  check('Phishing indicators include raw IP signal', phishRes.body.detected_indicators.some(i => i.toLowerCase().includes('ip address') || i.toLowerCase().includes('raw ip')));

  // Render in extension popup logic
  popupModule.renderResult(phishRes.body);
  check('Extension renders phishing-banner', mockDomElements['verdict-banner'].classList.contains('phishing-banner'));
  check('Extension displays "Phishing Threat Detected"', mockDomElements['verdict-title'].textContent === 'Phishing Threat Detected');

  // --- ITEM 3: SPA / DEGRADED URL END-TO-END ---
  console.log('\n--- MATRIX 3: SPA / DEGRADED URL END-TO-END (https://ps.bitsathy.ac.in) ---');
  const spaRes = await requestPost(API_URL, { url: 'https://ps.bitsathy.ac.in' });
  check('SPA URL returns HTTP 200', spaRes.status === 200);
  check('SPA URL is NOT classified as raw phishing false positive', spaRes.body.is_phishing === false);
  check('SPA URL risk_level is bounded (medium or low)', ['medium', 'low'].includes(spaRes.body.risk_level), `risk_level = ${spaRes.body.risk_level}`);
  check('SPA URL status is suspicious or safe', ['suspicious', 'safe'].includes(spaRes.body.status), `status = ${spaRes.body.status}`);
  check('SPA URL has content_rendering_incomplete === true', spaRes.body.content_rendering_incomplete === true, `val = ${spaRes.body.content_rendering_incomplete}`);
  check('SPA indicators explain client-side rendering', spaRes.body.detected_indicators.some(i => i.toLowerCase().includes('javascript') || i.toLowerCase().includes('rendered') || i.toLowerCase().includes('visibility')));

  // Render in extension popup logic
  popupModule.renderResult(spaRes.body);
  check('Extension renders suspicious or safe banner for SPA (not phishing banner)', !mockDomElements['verdict-banner'].classList.contains('phishing-banner'));
  check('Extension degraded notice is hidden when html_available=true', mockDomElements['degraded-notice'].classList.contains('hidden'));
  check('Extension SPA notice is VISIBLE when content_rendering_incomplete=true', !mockDomElements['spa-notice'].classList.contains('hidden'));

  // --- ITEM 4: ERROR / INVALID URL END-TO-END ---
  console.log('\n--- MATRIX 4: ERROR / INVALID URL END-TO-END ---');
  // 4a. Empty string
  const emptyRes = await requestPost(API_URL, { url: '' });
  check('Empty string returns 200 with status="error"', emptyRes.status === 200 && emptyRes.body.status === 'error');
  check('Empty string provides error_message', typeof emptyRes.body.error_message === 'string' && emptyRes.body.error_message.length > 0);

  // 4b. Javascript scheme
  const jsRes = await requestPost(API_URL, { url: 'javascript:alert(1)' });
  check('Javascript scheme returns 200 with status="error"', jsRes.status === 200 && jsRes.body.status === 'error');
  check('Javascript scheme identifies unsupported scheme', jsRes.body.error_message.includes('javascript'));

  // 4c. Oversized URL (>2048 chars)
  const overRes = await requestPost(API_URL, { url: 'https://example.com/' + 'a'.repeat(2100) });
  check('Oversized URL returns 422 Unprocessable Entity', overRes.status === 422);

  // Extension client-side pre-validation
  check('Extension checkUrlAnalyzable rejects chrome://', popupModule.checkUrlAnalyzable('chrome://settings').analyzable === false);
  check('Extension checkUrlAnalyzable rejects file://', popupModule.checkUrlAnalyzable('file:///c:/test').analyzable === false);

  // --- ITEM 6: CORS VERIFICATION ---
  console.log('\n--- MATRIX 6: CORS VERIFICATION ---');
  const webOrigin = 'http://localhost:5173';
  const extOrigin = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop';

  // Preflight Web
  const webOpt = await requestOptions(API_URL, {
    'Origin': webOrigin,
    'Access-Control-Request-Method': 'POST',
    'Access-Control-Request-Headers': 'Content-Type',
  });
  check('Web origin preflight returns 200', webOpt.status === 200);
  check('Web origin preflight has Access-Control-Allow-Origin', Boolean(webOpt.headers['access-control-allow-origin']));

  // POST Web
  const webPost = await requestPost(API_URL, { url: 'https://example.com' }, { 'Origin': webOrigin });
  check('Web origin POST has Access-Control-Allow-Origin', Boolean(webPost.headers['access-control-allow-origin']));

  // Preflight Extension
  const extOpt = await requestOptions(API_URL, {
    'Origin': extOrigin,
    'Access-Control-Request-Method': 'POST',
    'Access-Control-Request-Headers': 'Content-Type',
  });
  check('Extension origin preflight returns 200', extOpt.status === 200);
  check('Extension origin preflight has Access-Control-Allow-Origin', Boolean(extOpt.headers['access-control-allow-origin']));

  // POST Extension
  const extPost = await requestPost(API_URL, { url: 'https://example.com' }, { 'Origin': extOrigin });
  check('Extension origin POST has Access-Control-Allow-Origin', Boolean(extPost.headers['access-control-allow-origin']));

  // --- ITEM 7: RESPONSE SCHEMA CONSISTENCY ---
  console.log('\n--- MATRIX 7: RESPONSE SCHEMA CONSISTENCY ---');
  const expectedFields = [
    'url', 'status', 'confidence', 'risk_level', 'is_phishing',
    'html_available', 'content_rendering_incomplete', 'detected_indicators', 'url_features_summary',
    'error_message', 'analysis_timestamp', 'execution_time_ms'
  ];
  expectedFields.forEach(field => {
    check(`PredictResponse includes schema field "${field}"`, field in safeRes.body, `val: ${JSON.stringify(safeRes.body[field])}`);
  });

  check('PredictResponse includes content_rendering_incomplete boolean', typeof safeRes.body.content_rendering_incomplete === 'boolean');

  // --- ITEM 8: PERFORMANCE SANITY CHECK ---
  console.log('\n--- MATRIX 8: PERFORMANCE SANITY CHECK ---');
  const t0 = Date.now();
  const perfRes = await requestPost(API_URL, { url: 'https://example.com' });
  const roundtrip = Date.now() - t0;
  check('Response roundtrip time is within reasonable bounds (<5000ms)', roundtrip < 5000, `${roundtrip}ms`);
  check('Execution time reported by backend is positive', perfRes.body.execution_time_ms > 0, `${perfRes.body.execution_time_ms.toFixed(1)}ms`);

  console.log('\n============================================================');
  console.log(`ALL ${passCount}/${testCount} MATRIX CHECKS PASSED! 🚀`);
  console.log('============================================================\n');
}

runMatrix().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
