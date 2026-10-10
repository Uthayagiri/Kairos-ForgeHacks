/**
 * PhishGuard AI — Controlled High-Risk Navigation Interception Integration Test
 *
 * Exercises the end-to-end navigation interception flow in REAL CHROMIUM:
 * 1. Spins up a local loopback HTTP server (127.0.0.1) on an ephemeral port as a controlled destination.
 * 2. Launches real Chromium with the unpacked PhishGuard AI extension loaded.
 * 3. Connects to the real background service worker runtime.
 * 4. Supplies a synthetic high-risk API response (87.7% Phishing, matching the unencrypted HTTP login signature).
 * 5. Navigates a Chromium tab to the controlled local URL (zero external network requests).
 * 6. Verifies that the service worker intercepts onBeforeNavigate and redirects the tab to warning.html.
 * 7. Asserts that the warning page DOM correctly displays the target URL, 87.7% risk score, and threat indicators.
 */

import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const puppeteer = require('../../frontend/node_modules/puppeteer');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const extensionPath = path.resolve(__dirname, '..');

async function runControlledHighRiskTest() {
  console.log('===============================================================');
  console.log(' PhishGuard AI — Controlled High-Risk Navigation Interception');
  console.log('===============================================================');

  let localServer = null;
  let browser = null;

  try {
    // 1. Start local loopback HTTP server on ephemeral port (avoids conflicts and external network access)
    localServer = http.createServer((req, res) => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><head><title>Original Destination</title></head><body>Simulated Login Page</body></html>');
    });

    await new Promise((resolve) => localServer.listen(0, '127.0.0.1', resolve));
    const assignedPort = localServer.address().port;
    const targetUrl = `http://127.0.0.1:${assignedPort}/login`;

    console.log(`✓ Local test server bound to loopback: ${targetUrl} (ZERO external traffic)`);

    // 2. Launch Chromium with extension loaded
    console.log(`Launching real Chromium with unpacked extension: ${extensionPath}...`);
    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
        '--no-sandbox',
        '--disable-setuid-sandbox',
      ],
    });
    console.log('✓ Real Chromium launched successfully.');

    // 3. Locate active Background Service Worker target
    let swTarget = null;
    for (let attempt = 0; attempt < 30; attempt++) {
      swTarget = browser.targets().find(
        (t) => t.type() === 'service_worker' && t.url().includes('service-worker.js')
      );
      if (swTarget) break;
      await new Promise((r) => setTimeout(r, 200));
    }

    if (!swTarget) {
      throw new Error('Background service worker target failed to initialize in Chromium');
    }
    console.log(`✓ Active Background Service Worker detected: ${swTarget.url()}`);

    const worker = await swTarget.worker();
    if (!worker) {
      throw new Error('Could not acquire WebWorker handle from service worker target');
    }

    // 4. Construct synthetic high-risk API response (modeling http://example.com/login at 87.7%)
    const syntheticHighRiskResult = {
      url: targetUrl,
      status: 'phishing',
      risk_level: 'high',
      risk_score: 87.7,
      confidence: 0.8772,
      is_phishing: true,
      detected_indicators: [
        'URL contains sensitive or authentication-related keywords (e.g., login, verify, account, secure).',
        'Connection does not use secure HTTPS encryption.',
        'Live HTML content could not be inspected (site unreachable); high-risk verdict is driven by strong URL-level threat signals.'
      ],
      signals_breakdown: {
        url_signals: { uses_https: false, has_suspicious_keywords: true, num_subdomains: 0 },
        domain_signals: { tld: '.com', ssrf_protection: 'Passed' },
        html_signals: { html_available: false }
      },
      verified: true
    };

    // 5. Inject mock fetch into the service worker execution context
    await worker.evaluate((mockPayload) => {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = async (input, init) => {
        const urlStr = typeof input === 'string' ? input : input?.url || '';
        if (urlStr.includes('/api/analyze') || urlStr.includes('/predict')) {
          return {
            ok: true,
            status: 200,
            json: async () => mockPayload,
          };
        }
        return originalFetch(input, init);
      };
    }, syntheticHighRiskResult);
    console.log('✓ Synthetic high-risk API response injected into Service Worker fetch handler.');

    // 6. Open a new Chromium tab and trigger navigation
    const page = await browser.newPage();
    console.log(`Navigating tab to target URL: ${targetUrl}...`);

    try {
      await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 10000 });
    } catch (navErr) {
      // Expected: Chromium aborts navigation to targetUrl when chrome.tabs.update() redirects
      console.log(`ℹ Initial navigation intercepted by extension (${navErr.message.split('\n')[0]})`);
    }

    // 7. Verify redirection to warning interstitial
    await page.waitForFunction(
      () => window.location.href.includes('warning/warning.html'),
      { timeout: 8000 }
    );
    const finalUrl = page.url();
    console.log(`✓ Tab successfully intercepted & redirected to warning page:`);
    console.log(`  ${finalUrl.substring(0, 100)}...`);

    // 8. Inspect Warning Page DOM
    await page.waitForSelector('#target-url', { timeout: 5000 });
    await page.waitForSelector('#risk-score-value', { timeout: 5000 });
    await page.waitForSelector('#risk-badge', { timeout: 5000 });

    const displayedTargetUrl = await page.$eval('#target-url', (el) => el.textContent.trim());
    const displayedRiskScore = await page.$eval('#risk-score-value', (el) => el.textContent.trim());
    const displayedBadge = await page.$eval('#risk-badge', (el) => el.textContent.trim());
    const threatItems = await page.$$eval('#threat-list li', (items) => items.map((li) => li.textContent.trim()));

    console.log('\n--- Forensic Verification in Real Chromium DOM ---');
    console.log(`  - Target URL displayed: "${displayedTargetUrl}"`);
    console.log(`  - Risk Score displayed: "${displayedRiskScore}"`);
    console.log(`  - Risk Badge displayed: "${displayedBadge}"`);
    console.log(`  - Threat items count:   ${threatItems.length}`);
    threatItems.forEach((item, i) => console.log(`      [${i + 1}] ${item}`));

    // Assertions
    if (displayedTargetUrl !== targetUrl) {
      throw new Error(`Target URL mismatch: expected "${targetUrl}", got "${displayedTargetUrl}"`);
    }
    if (displayedRiskScore !== '87.7%') {
      throw new Error(`Risk score mismatch: expected "87.7%", got "${displayedRiskScore}"`);
    }
    if (!displayedBadge.includes('CRITICAL PHISHING THREAT')) {
      throw new Error(`Risk badge mismatch: expected 'CRITICAL PHISHING THREAT', got "${displayedBadge}"`);
    }
    if (threatItems.length !== 3) {
      throw new Error(`Threat items count mismatch: expected 3, got ${threatItems.length}`);
    }

    // 9. Verify Override Panel expands
    await page.click('#toggle-override-btn');
    const overrideVisible = await page.$eval('#override-panel', (el) => !el.classList.contains('hidden'));
    if (!overrideVisible) {
      throw new Error('Override panel failed to expand on click');
    }
    console.log('✓ Override panel expands correctly in warning interstitial.');

    console.log('===============================================================');
    console.log(' CONTROLLED TEST RESULT: ALL ASSERTIONS PASSED (100% SUCCESS)');
    console.log('===============================================================');

  } finally {
    if (browser) await browser.close();
    if (localServer) {
      await new Promise((resolve) => localServer.close(resolve));
    }
  }
}

runControlledHighRiskTest().catch((err) => {
  console.error('✗ Controlled test failed:', err);
  process.exit(1);
});
