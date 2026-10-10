/**
 * PhishGuard AI — Phase 2 Extension Navigation Interception Automated Test Suite
 *
 * Deterministic unit and integration tests covering:
 * 1. High-risk destination interception & redirection to warning.html.
 * 2. Low-risk destination allowed normally.
 * 3. Medium-risk destination caution policy.
 * 4. Backend timeout & backend unavailable failure modes.
 * 5. Malformed backend response handling.
 * 6. Repeated navigation events & in-flight deduplication.
 * 7. Extension warning page loop prevention.
 * 8. Concurrent multi-tab navigation isolation.
 * 9. Complex, Unicode, query param, and fragment URL handling.
 * 10. User override flow and bypass permission.
 * 11. Bounded LRU cache eviction and TTL expiration.
 */

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const serviceWorker = require('../background/service-worker.js');

const {
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
} = serviceWorker;

// Helper: Setup mock Chrome API environment
function setupMockChrome() {
  const tabsUpdated = [];
  const badgesUpdated = [];

  globalThis.chrome = {
    runtime: {
      getURL: (path = '') => `chrome-extension://phishguard-test-extension-id/${path}`,
      onInstalled: { addListener: () => {} },
      onMessage: { addListener: () => {} },
    },
    webNavigation: {
      onBeforeNavigate: { addListener: () => {} },
    },
    action: {
      setBadgeText: ({ text, tabId }) => {
        badgesUpdated.push({ text, tabId });
      },
      setBadgeBackgroundColor: ({ color, tabId }) => {
        const last = badgesUpdated[badgesUpdated.length - 1];
        if (last) last.color = color;
      },
    },
    tabs: {
      update: (tabId, updateProps) => {
        tabsUpdated.push({ tabId, ...updateProps });
        return Promise.resolve({ id: tabId, ...updateProps });
      },
    },
  };

  return { tabsUpdated, badgesUpdated };
}

async function runTestSuite() {
  console.log('===============================================================');
  console.log(' PhishGuard AI — Phase 2 Extension Automated Test Suite');
  console.log('===============================================================');

  let passedCount = 0;
  let failedCount = 0;

  async function test(name, fn) {
    // Reset state before each test
    threatCache.clear();
    overrideManager.clear();
    inFlightEvaluations.clear();
    tabActiveNavigations.clear();

    try {
      await fn();
      console.log(`  ✓ [PASS] ${name}`);
      passedCount++;
    } catch (err) {
      console.error(`  ✗ [FAIL] ${name}`);
      console.error(`    ${err.stack || err.message}`);
      failedCount++;
    }
  }

  // ---------------------------------------------------------------------------
  // Test 1: High-risk destination intercepted and redirected to warning page
  // ---------------------------------------------------------------------------
  await test('1. High-risk destination intercepted and redirected to warning page', async () => {
    const { tabsUpdated, badgesUpdated } = setupMockChrome();
    const targetUrl = 'http://bank-login-update-security.phishing.cc/login';

    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({
        url: targetUrl,
        status: 'phishing',
        risk_level: 'high',
        risk_score: 95.5,
        confidence: 0.955,
        is_phishing: true,
        detected_indicators: ['Credential harvesting form detected', 'Suspicious keywords'],
        signals_breakdown: { url_signals: { has_suspicious_keywords: true } },
      }),
    });

    await handleBeforeNavigate({ tabId: 101, url: targetUrl, frameId: 0 });

    assert.equal(tabsUpdated.length, 1, 'Should call chrome.tabs.update exactly once');
    assert.equal(tabsUpdated[0].tabId, 101);
    assert.ok(tabsUpdated[0].url.includes('warning/warning.html'), 'Redirect URL must point to warning.html');
    assert.ok(tabsUpdated[0].url.includes(encodeURIComponent(targetUrl)), 'Redirect URL must contain encoded target');
    assert.ok(tabsUpdated[0].url.includes('risk=95.5'), 'Redirect URL must carry risk score');

    const badge = badgesUpdated.find((b) => b.tabId === 101 && b.text === 'PHISH');
    assert.ok(badge, 'Should set PHISH badge for high-risk navigation');
    assert.equal(badge.color, '#ef4444');
  });

  // ---------------------------------------------------------------------------
  // Test 2: Low-risk destination allowed normally without redirect
  // ---------------------------------------------------------------------------
  await test('2. Low-risk destination allowed normally without redirect', async () => {
    const { tabsUpdated, badgesUpdated } = setupMockChrome();
    const targetUrl = 'https://en.wikipedia.org/wiki/Computer_security';

    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({
        url: targetUrl,
        status: 'safe',
        risk_level: 'low',
        risk_score: 8.0,
        confidence: 0.08,
        is_phishing: false,
        detected_indicators: ['Encrypted HTTPS connection', 'Standard domain structure'],
      }),
    });

    await handleBeforeNavigate({ tabId: 102, url: targetUrl, frameId: 0 });

    assert.equal(tabsUpdated.length, 0, 'Must NOT redirect safe destination');
    const badge = badgesUpdated.find((b) => b.tabId === 102 && b.text === 'OK');
    assert.ok(badge, 'Should set OK badge for safe navigation');
    assert.equal(badge.color, '#10b981');
  });

  // ---------------------------------------------------------------------------
  // Test 3: Medium-risk destination follows documented policy
  // ---------------------------------------------------------------------------
  await test('3. Medium-risk destination follows documented policy (allow with caution badge)', async () => {
    const { tabsUpdated, badgesUpdated } = setupMockChrome();
    const targetUrl = 'http://free-giveaway-promo.net/claim';

    globalThis.fetch = async () => ({
      ok: true,
      json: async () => ({
        url: targetUrl,
        status: 'suspicious',
        risk_level: 'medium',
        risk_score: 52.0,
        confidence: 0.52,
        is_phishing: false,
        detected_indicators: ['Unencrypted HTTP connection', 'Promotional keywords'],
      }),
    });

    await handleBeforeNavigate({ tabId: 103, url: targetUrl, frameId: 0 });

    assert.equal(tabsUpdated.length, 0, 'Medium-risk destination should not be hard-blocked');
    const badge = badgesUpdated.find((b) => b.tabId === 103 && b.text === 'WARN');
    assert.ok(badge, 'Should set WARN badge for suspicious/medium-risk navigation');
    assert.equal(badge.color, '#f59e0b');
  });

  // ---------------------------------------------------------------------------
  // Test 4: Backend timeout and backend unavailable
  // ---------------------------------------------------------------------------
  await test('4. Backend timeout and backend unavailable (fails safely without false Safe)', async () => {
    const { tabsUpdated, badgesUpdated } = setupMockChrome();
    const targetUrl = 'https://slow-or-unreachable-server.com/';

    // Simulate timeout (AbortError)
    globalThis.fetch = async () => {
      const err = new Error('The operation was aborted');
      err.name = 'AbortError';
      throw err;
    };

    await handleBeforeNavigate({ tabId: 104, url: targetUrl, frameId: 0 });

    assert.equal(tabsUpdated.length, 0, 'Timeout should fail-open rather than freezing browser indefinitely');
    const badge = badgesUpdated.find((b) => b.tabId === 104 && b.text === '?');
    assert.ok(badge, 'Should set ? badge on timeout / error');

    // Verify cache does NOT mark this destination as safe
    const cached = threatCache.get(targetUrl);
    assert.ok(cached, 'Failure must be cached briefly');
    assert.equal(cached.status, 'error');
    assert.equal(cached.verified, false, 'Must NOT mark failed request as verified');
  });

  // ---------------------------------------------------------------------------
  // Test 5: Malformed backend response
  // ---------------------------------------------------------------------------
  await test('5. Malformed backend response handled safely', async () => {
    const { tabsUpdated } = setupMockChrome();
    const targetUrl = 'https://malformed-response.com/';

    // Simulate invalid non-JSON / server crash HTML response
    globalThis.fetch = async () => ({
      ok: false,
      status: 502,
      json: async () => { throw new Error('Unexpected token < in JSON at position 0'); },
    });

    await handleBeforeNavigate({ tabId: 105, url: targetUrl, frameId: 0 });

    assert.equal(tabsUpdated.length, 0);
    const cached = threatCache.get(targetUrl);
    assert.equal(cached.status, 'error');
    assert.equal(cached.verified, false);
  });

  // ---------------------------------------------------------------------------
  // Test 6: In-flight deduplication on repeated navigation events
  // ---------------------------------------------------------------------------
  await test('6. Repeated navigation events & in-flight deduplication', async () => {
    setupMockChrome();
    const targetUrl = 'https://duplicate-check.com/test';
    let fetchCalls = 0;

    globalThis.fetch = async () => {
      fetchCalls++;
      // Simulate artificial delay
      await new Promise((r) => setTimeout(r, 20));
      return {
        ok: true,
        json: async () => ({
          url: targetUrl,
          status: 'safe',
          risk_level: 'low',
          risk_score: 5.0,
        }),
      };
    };

    // Trigger multiple simultaneous evaluations for the exact same URL
    const p1 = evaluateUrlWithBackend(targetUrl);
    const p2 = evaluateUrlWithBackend(targetUrl);
    const p3 = evaluateUrlWithBackend(targetUrl);

    const [r1, r2, r3] = await Promise.all([p1, p2, p3]);

    assert.equal(fetchCalls, 1, 'In-flight deduplication must make only 1 network fetch');
    assert.equal(r1.status, 'safe');
    assert.equal(r2.status, 'safe');
    assert.equal(r3.status, 'safe');
  });

  // ---------------------------------------------------------------------------
  // Test 7: Warning page does not trigger an interception loop
  // ---------------------------------------------------------------------------
  await test('7. Warning page does not trigger an interception loop', () => {
    setupMockChrome();
    const warningPageUrl = 'chrome-extension://phishguard-test-extension-id/warning/warning.html?url=http%3A%2F%2Fbad.com';

    const eligible = isEligibleNavigation({
      tabId: 107,
      url: warningPageUrl,
      frameId: 0,
    });

    assert.equal(eligible, false, 'Warning page must NEVER be eligible for interception (prevents loops)');

    const nonWeb = isEligibleNavigation({ tabId: 107, url: 'chrome://settings', frameId: 0 });
    assert.equal(nonWeb, false, 'Internal chrome:// URLs must not be intercepted');

    const iframe = isEligibleNavigation({ tabId: 107, url: 'https://example.com/iframe', frameId: 1 });
    assert.equal(iframe, false, 'Subframes (frameId !== 0) must not be intercepted');
  });

  // ---------------------------------------------------------------------------
  // Test 8: Multiple tabs navigating concurrently
  // ---------------------------------------------------------------------------
  await test('8. Multiple tabs navigating concurrently remain isolated', async () => {
    const { tabsUpdated } = setupMockChrome();
    const evilUrl = 'http://concurrent-phish.com/';
    const goodUrl = 'https://concurrent-safe.com/';

    globalThis.fetch = async (endpoint, opts) => {
      const body = JSON.parse(opts.body);
      if (body.url === evilUrl) {
        return {
          ok: true,
          json: async () => ({
            url: evilUrl,
            status: 'phishing',
            risk_level: 'high',
            risk_score: 91.0,
          }),
        };
      }
      return {
        ok: true,
        json: async () => ({
          url: goodUrl,
          status: 'safe',
          risk_level: 'low',
          risk_score: 10.0,
        }),
      };
    };

    // Navigate Tab 1 to Evil, Tab 2 to Good concurrently
    await Promise.all([
      handleBeforeNavigate({ tabId: 201, url: evilUrl, frameId: 0 }),
      handleBeforeNavigate({ tabId: 202, url: goodUrl, frameId: 0 }),
    ]);

    // Tab 201 should be redirected; Tab 202 should not
    const tab201Update = tabsUpdated.find((u) => u.tabId === 201);
    const tab202Update = tabsUpdated.find((u) => u.tabId === 202);

    assert.ok(tab201Update, 'Tab 201 (evil) must be redirected');
    assert.ok(tab201Update.url.includes('warning/warning.html'));
    assert.equal(tab202Update, undefined, 'Tab 202 (safe) must NOT be redirected');
  });

  // ---------------------------------------------------------------------------
  // Test 9: Safe handling of complex, Unicode, and query-param URLs
  // ---------------------------------------------------------------------------
  await test('9. Safe handling of query parameters, fragments, and Unicode encodings', () => {
    setupMockChrome();
    const complexUrl = 'https://test-site.org:8443/login/path?token=xyz%20123&redirect=https%3A%2F%2Fother.com#anchor-section';
    const warningUrl = buildWarningUrl(complexUrl, {
      risk_score: 88,
      status: 'phishing',
      detected_indicators: ['Credential query token', 'Non-standard port'],
      signals_breakdown: {},
    });

    assert.ok(warningUrl.includes('url=https%3A%2F%2Ftest-site.org%3A8443%2Flogin%2Fpath'), 'URL must be URI-encoded properly');
    assert.ok(warningUrl.includes('token%3Dxyz'), 'Query parameters preserved encoded');

    // Test Unicode domain
    const unicodeUrl = 'https://xn--e1afmkfd.xn--p1ai/path';
    const warningUnicode = buildWarningUrl(unicodeUrl, { risk_score: 90 });
    assert.ok(warningUnicode.includes('xn--e1afmkfd'), 'Punycode/Unicode preserved');
  });

  // ---------------------------------------------------------------------------
  // Test 10: User override flow
  // ---------------------------------------------------------------------------
  await test('10. User override flow permits destination without redirect', async () => {
    const { tabsUpdated, badgesUpdated } = setupMockChrome();
    const dangerousUrl = 'http://explicit-override-test.com/login';

    // Seed cache as phishing
    threatCache.set(dangerousUrl, {
      url: dangerousUrl,
      status: 'phishing',
      risk_level: 'high',
      risk_score: 98,
    });

    // 1. Without override: gets intercepted
    await handleBeforeNavigate({ tabId: 301, url: dangerousUrl, frameId: 0 });
    assert.equal(tabsUpdated.length, 1);
    assert.ok(tabsUpdated[0].url.includes('warning/warning.html'));

    // 2. User confirms override on warning page
    overrideManager.addOverride(dangerousUrl);
    assert.equal(overrideManager.hasOverride(dangerousUrl), true);

    // 3. User navigates back to dangerousUrl: MUST NOT be intercepted
    tabsUpdated.length = 0;
    await handleBeforeNavigate({ tabId: 301, url: dangerousUrl, frameId: 0 });

    assert.equal(tabsUpdated.length, 0, 'Overridden URL must NOT be intercepted again');
    const overrideBadge = badgesUpdated.find((b) => b.tabId === 301 && b.text === 'BYPASS');
    assert.ok(overrideBadge, 'Should display BYPASS badge on overridden destination');
  });

  // ---------------------------------------------------------------------------
  // Test 11: Cache capacity bounding and TTL expiration
  // ---------------------------------------------------------------------------
  await test('11. Cache capacity bounding and TTL expiration', () => {
    const cache = new BoundedThreatCache(3, 50); // Max 3 items, 50ms TTL

    cache.set('http://site1.com', { id: 1 });
    cache.set('http://site2.com', { id: 2 });
    cache.set('http://site3.com', { id: 3 });

    assert.equal(cache.size, 3);
    assert.ok(cache.get('http://site1.com') !== null);

    // Insert 4th item: should evict site2 (site1 was touched by get, so site2 is oldest)
    cache.set('http://site4.com', { id: 4 });
    assert.equal(cache.size, 3);
    assert.ok(cache.get('http://site4.com') !== null);

    // Wait for TTL expiration (55ms > 50ms)
    return new Promise((resolve) => {
      setTimeout(() => {
        assert.equal(cache.get('http://site1.com'), null, 'Expired items must return null');
        assert.equal(cache.get('http://site4.com'), null, 'Expired items must return null');
        resolve();
      }, 60);
    });
  });

  // ---------------------------------------------------------------------------
  // Summary Report
  // ---------------------------------------------------------------------------
  console.log('===============================================================');
  console.log(` Test Results: ${passedCount} Passed, ${failedCount} Failed`);
  console.log('===============================================================');

  if (failedCount > 0) {
    process.exit(1);
  }
}

runTestSuite();
