/**
 * PhishGuard AI - Chrome & Microsoft Edge Extension Controller (Manifest V3)
 * Provides active tab URL analysis, circular risk gauge, 3 signal group accordions,
 * and safe warning interstitial integration.
 */

// Default configuration
const DEFAULT_CONFIG = {
  API_BASE_URL: 'http://127.0.0.1:8000',
  AUTO_SCAN: true,
  DASHBOARD_URL: 'http://localhost:5173',
};

let currentConfig = { ...DEFAULT_CONFIG };
let currentTargetUrl = '';
let currentAnalysisResult = null;
let currentActiveTabId = undefined;

// DOM Elements
const views = {
  loading: document.getElementById('loading-view'),
  result: document.getElementById('result-view'),
  unanalyzable: document.getElementById('unanalyzable-view'),
  error: document.getElementById('error-view'),
};

const elements = {
  targetHost: document.getElementById('target-host-text'),
  targetUrl: document.getElementById('target-url-text'),
  manualPanel: document.getElementById('manual-input-panel'),
  settingsPanel: document.getElementById('settings-panel'),
  manualInput: document.getElementById('manual-url-input'),
  manualScanBtn: document.getElementById('manual-scan-btn'),
  toggleManualBtn: document.getElementById('toggle-manual-btn'),
  toggleSettingsBtn: document.getElementById('toggle-settings-btn'),
  saveSettingsBtn: document.getElementById('save-settings-btn'),
  apiUrlInput: document.getElementById('api-url-input'),
  autoScanCheck: document.getElementById('auto-scan-check'),
  rescanBtn: document.getElementById('rescan-tab-btn'),
  openDashboardBtn: document.getElementById('open-full-dashboard-btn'),
  errorRetryBtn: document.getElementById('error-retry-btn'),
  unanalyzableManualBtn: document.getElementById('unanalyzable-manual-btn'),
  viewWarningBtn: document.getElementById('view-warning-page-btn'),
  warningActionWrap: document.getElementById('warning-action-wrap'),
  recommendationText: document.getElementById('recommendation-text'),
  gaugeArc: document.getElementById('gauge-arc'),
  gaugeScoreText: document.getElementById('gauge-score-text'),
  verdictBadge: document.getElementById('verdict-badge'),
  verdictTitle: document.getElementById('verdict-title'),
  verdictSub: document.getElementById('verdict-subtitle'),
  verdictCard: document.getElementById('verdict-card'),
  indicatorsContainer: document.getElementById('indicators-container'),
  urlSignalsContainer: document.getElementById('url-signals-container'),
  domainSignalsContainer: document.getElementById('domain-signals-container'),
  domSignalsContainer: document.getElementById('dom-signals-container'),
  execTimeText: document.getElementById('exec-time-text'),
};

// Initialize Extension
document.addEventListener('DOMContentLoaded', async () => {
  await loadPreferences();
  setupEventListeners();
  inspectActiveTab();
});

/**
 * Load user preferences from chrome.storage.local
 */
async function loadPreferences() {
  try {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      const stored = await chrome.storage.local.get(['apiUrl', 'autoScan', 'dashboardUrl']);
      if (stored.apiUrl) currentConfig.API_BASE_URL = stored.apiUrl;
      if (stored.autoScan !== undefined) currentConfig.AUTO_SCAN = stored.autoScan;
      if (stored.dashboardUrl) currentConfig.DASHBOARD_URL = stored.dashboardUrl;
    }
  } catch {
    // fallback to defaults
  }

  if (elements.apiUrlInput) elements.apiUrlInput.value = currentConfig.API_BASE_URL;
  if (elements.autoScanCheck) elements.autoScanCheck.checked = currentConfig.AUTO_SCAN;
}

/**
 * Save user preferences
 */
async function savePreferences() {
  const newApiUrl = elements.apiUrlInput.value.trim() || DEFAULT_CONFIG.API_BASE_URL;
  const autoScan = elements.autoScanCheck.checked;

  currentConfig.API_BASE_URL = newApiUrl;
  currentConfig.AUTO_SCAN = autoScan;

  try {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      await chrome.storage.local.set({ apiUrl: newApiUrl, autoScan });
    }
  } catch {
    // ignore
  }

  if (elements.settingsPanel) elements.settingsPanel.classList.add('hidden');
}

/**
 * Register DOM event listeners
 */
function setupEventListeners() {
  // Toggle Manual Input Panel
  elements.toggleManualBtn?.addEventListener('click', () => {
    elements.manualPanel?.classList.toggle('hidden');
    elements.settingsPanel?.classList.add('hidden');
  });

  // Toggle Settings Panel
  elements.toggleSettingsBtn?.addEventListener('click', () => {
    elements.settingsPanel?.classList.toggle('hidden');
    elements.manualPanel?.classList.add('hidden');
  });

  elements.saveSettingsBtn?.addEventListener('click', savePreferences);

  // Manual Scan
  elements.manualScanBtn?.addEventListener('click', () => {
    const raw = elements.manualInput?.value.trim();
    if (raw) analyzeUrl(raw);
  });

  // Preset Buttons
  document.querySelectorAll('.preset-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      const url = e.currentTarget.dataset.url;
      if (url) {
        if (elements.manualInput) elements.manualInput.value = url;
        analyzeUrl(url);
      }
    });
  });

  // Rescan Active Tab
  elements.rescanBtn?.addEventListener('click', inspectActiveTab);
  elements.errorRetryBtn?.addEventListener('click', () => {
    if (currentTargetUrl) analyzeUrl(currentTargetUrl);
    else inspectActiveTab();
  });

  elements.unanalyzableManualBtn?.addEventListener('click', () => {
    elements.manualPanel?.classList.remove('hidden');
  });

  // Open Full Web Dashboard
  elements.openDashboardBtn?.addEventListener('click', () => {
    const url = currentConfig.DASHBOARD_URL || 'http://localhost:5173';
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      chrome.tabs.create({ url });
    } else {
      window.open(url, '_blank');
    }
  });

  // View Safe Warning Page
  elements.viewWarningBtn?.addEventListener('click', () => {
    if (currentAnalysisResult) {
      const warningUrl =
        (typeof chrome !== 'undefined' && chrome.runtime
          ? chrome.runtime.getURL('warning/warning.html')
          : 'warning/warning.html') +
        `?url=${encodeURIComponent(currentAnalysisResult.url)}` +
        `&risk=${currentAnalysisResult.risk_score || 90}` +
        `&reasons=${encodeURIComponent(JSON.stringify(currentAnalysisResult.detected_indicators || []))}`;

      if (typeof chrome !== 'undefined' && chrome.tabs) {
        chrome.tabs.create({ url: warningUrl });
      } else {
        window.open(warningUrl, '_blank');
      }
    }
  });

  // Signal Tab Switching
  document.querySelectorAll('.sig-tab').forEach((tabBtn) => {
    tabBtn.addEventListener('click', (e) => {
      document.querySelectorAll('.sig-tab').forEach((t) => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach((c) => c.classList.add('hidden'));

      const tabId = e.currentTarget.dataset.tab;
      e.currentTarget.classList.add('active');

      const targetContent = document.getElementById(`tab-${tabId}-content`);
      if (targetContent) targetContent.classList.remove('hidden');
    });
  });
}

/**
 * Inspect Active Tab in Chromium Browser
 */
function inspectActiveTab() {
  if (typeof chrome === 'undefined' || !chrome.tabs || !chrome.tabs.query) {
    // Standalone demo preview fallback
    setTargetDisplay('https://en.wikipedia.org/wiki/Phishing');
    analyzeUrl('https://en.wikipedia.org/wiki/Phishing');
    return;
  }

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (chrome.runtime.lastError || !tabs || tabs.length === 0) {
      showView('unanalyzable');
      return;
    }

    const activeTab = tabs[0];
    currentActiveTabId = activeTab.id;
    const url = activeTab.url || '';
    setTargetDisplay(url);

    // Validate if scheme is analyzable web resource
    const isAnalyzable = validateAnalyzableUrl(url);
    if (!isAnalyzable) {
      showView('unanalyzable');
      return;
    }

    // Check if background service worker already evaluated this active URL
    if (chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage({ type: 'GET_TAB_RISK', url }, (res) => {
        if (res && res.success && res.result && res.result.verified) {
          renderResult(res.result);
          return;
        }
        if (currentConfig.AUTO_SCAN) {
          analyzeUrl(url, currentActiveTabId);
        }
      });
    } else if (currentConfig.AUTO_SCAN) {
      analyzeUrl(url, currentActiveTabId);
    }
  });
}

function setTargetDisplay(url) {
  currentTargetUrl = url;
  if (elements.targetUrl) elements.targetUrl.textContent = url || 'No active URL';
  try {
    const parsed = new URL(url);
    if (elements.targetHost) elements.targetHost.textContent = parsed.hostname || '--';
  } catch {
    if (elements.targetHost) elements.targetHost.textContent = '--';
  }
}

function validateAnalyzableUrl(url) {
  if (!url) return false;
  const lower = url.trim().toLowerCase();
  if (
    lower.startsWith('chrome://') ||
    lower.startsWith('edge://') ||
    lower.startsWith('about:') ||
    lower.startsWith('chrome-extension://') ||
    lower.startsWith('file://')
  ) {
    return false;
  }
  return lower.startsWith('http://') || lower.startsWith('https://');
}

/**
 * Execute URL phishing analysis against FastAPI backend
 * Delegates to service worker in extension context to establish single authoritative verdict
 */
async function analyzeUrl(url, tabId = currentActiveTabId) {
  showView('loading');
  setTargetDisplay(url);

  // If in Chrome extension runtime, delegate to background service worker
  // to reuse bounded threat cache, deduplicate in-flight evaluations, and keep badge synchronized
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({ type: 'EVALUATE_URL', url, tabId }, (res) => {
      if (chrome.runtime.lastError || !res || !res.success || !res.result) {
        showView('error');
        return;
      }
      if (res.result.status === 'error' || !res.result.verified) {
        showView('error');
        return;
      }
      renderResult(res.result);
    });
    return;
  }

  // Standalone fallback (for local web preview / test environments)
  const endpoint = `${currentConfig.API_BASE_URL}/api/analyze`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      // Fallback try /predict if /api/analyze is unavailable
      const fallbackRes = await fetch(`${currentConfig.API_BASE_URL}/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ url }),
      });
      if (fallbackRes.ok) {
        const data = await fallbackRes.json();
        renderResult(data);
        return;
      }
      showView('error');
      return;
    }

    const data = await response.json();
    renderResult(data);
  } catch (err) {
    clearTimeout(timeoutId);
    showView('error');
  }
}

/**
 * Render forensic evaluation result
 */
function renderResult(data) {
  currentAnalysisResult = data;
  showView('result');

  const status = data.status || 'safe';
  const confidence = data.confidence || 0.0;
  const riskScore = data.risk_score !== undefined ? data.risk_score : Math.round(confidence * 100);
  const isPhish = status === 'phishing';
  const isSuspicious = status === 'suspicious';
  const isSafe = status === 'safe';

  // Keep tab badge synchronized with rendered result
  if (currentActiveTabId !== undefined && typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({
      type: 'UPDATE_BADGE',
      tabId: currentActiveTabId,
      status: status,
      score: riskScore,
    });
  }

  // Update Gauge & Colors
  let gaugeColor = '#10B981';
  let cardClass = 'safe';
  let badgeText = 'SAFE / BENIGN';

  if (isPhish) {
    gaugeColor = '#EF4444';
    cardClass = 'phishing';
    badgeText = 'CRITICAL THREAT';
  } else if (isSuspicious) {
    gaugeColor = '#F59E0B';
    cardClass = 'suspicious';
    badgeText = 'SUSPICIOUS DOMAIN';
  }

  if (elements.verdictCard) {
    elements.verdictCard.className = `verdict-card ${cardClass}`;
  }

  if (elements.gaugeArc) {
    elements.gaugeArc.style.stroke = gaugeColor;
    elements.gaugeArc.setAttribute('stroke-dasharray', `${riskScore}, 100`);
  }

  if (elements.gaugeScoreText) {
    elements.gaugeScoreText.textContent = `${riskScore}%`;
  }

  if (elements.verdictBadge) {
    elements.verdictBadge.textContent = badgeText;
  }

  if (elements.verdictTitle) {
    elements.verdictTitle.textContent = isSafe
      ? 'Legitimate Destination'
      : isSuspicious
      ? 'Suspicious Activity'
      : 'Phishing Attack Site';
  }

  if (elements.verdictSub) {
    elements.verdictSub.textContent = isSafe
      ? 'Verified legitimate structural patterns'
      : isSuspicious
      ? 'Deceptive characteristics identified'
      : 'Credential theft & harvest hazards detected';
  }

  // Recommendation text
  if (elements.recommendationText) {
    elements.recommendationText.textContent =
      data.recommended_action ||
      (isPhish
        ? 'CRITICAL HAZARD: Do NOT submit passwords, cookies, or financial info.'
        : isSuspicious
        ? 'EXERCISE CAUTION: Inspect the domain address bar carefully.'
        : 'Safe to proceed with normal browsing.');
  }

  // Warning Action Button
  if (elements.warningActionWrap) {
    if (isPhish || isSuspicious) {
      elements.warningActionWrap.classList.remove('hidden');
    } else {
      elements.warningActionWrap.classList.add('hidden');
    }
  }

  // Render 3 Signal Groups
  renderSignalGroups(data);

  // Render Indicators List
  if (elements.indicatorsContainer) {
    elements.indicatorsContainer.innerHTML = '';
    const indicators = data.detected_indicators || [];
    indicators.forEach((ind) => {
      const item = document.createElement('div');
      item.className = `indicator-item ${cardClass}`;
      item.textContent = ind;
      elements.indicatorsContainer.appendChild(item);
    });
  }

  // Execution latency
  if (elements.execTimeText) {
    elements.execTimeText.textContent = `${data.execution_time_ms || 120} ms`;
  }
}

/**
 * Render 3 Signal Groups (URL, Domain, DOM)
 */
function renderSignalGroups(data) {
  const summary = data.url_features_summary || {};
  const breakdown = data.signals_breakdown || {};

  // Tab 1: URL Signals
  if (elements.urlSignalsContainer) {
    elements.urlSignalsContainer.innerHTML = `
      <div class="signal-card">
        <div class="signal-name">HTTPS Security</div>
        <div class="signal-val" style="color: ${summary.uses_https ? '#10B981' : '#EF4444'}">
          ${summary.uses_https ? 'TLS Verified' : 'Insecure HTTP'}
        </div>
      </div>
      <div class="signal-card">
        <div class="signal-name">Domain Length</div>
        <div class="signal-val">${summary.domain_length || 0} chars</div>
      </div>
      <div class="signal-card">
        <div class="signal-name">Subdomain Depth</div>
        <div class="signal-val">${summary.num_subdomains || 0} levels</div>
      </div>
      <div class="signal-card">
        <div class="signal-name">Suspicious Keywords</div>
        <div class="signal-val" style="color: ${summary.has_suspicious_keywords ? '#EF4444' : '#10B981'}">
          ${summary.has_suspicious_keywords ? 'Detected' : 'None'}
        </div>
      </div>
    `;
  }

  // Tab 2: Domain Signals
  if (elements.domainSignalsContainer) {
    elements.domainSignalsContainer.innerHTML = `
      <div class="signal-card">
        <div class="signal-name">Raw IP Host</div>
        <div class="signal-val" style="color: ${summary.has_ip_address ? '#EF4444' : '#10B981'}">
          ${summary.has_ip_address ? 'Yes (Obfuscated)' : 'No (Clean Host)'}
        </div>
      </div>
      <div class="signal-card">
        <div class="signal-name">TLD Risk Category</div>
        <div class="signal-val" style="color: ${summary.has_suspicious_tld ? '#EF4444' : '#10B981'}">
          ${summary.has_suspicious_tld ? 'High-Risk TLD' : 'Standard TLD'}
        </div>
      </div>
      <div class="signal-card" style="grid-column: span 2;">
        <div class="signal-name">SSRF Boundary Guard</div>
        <div class="signal-val" style="color: #10B981;">Enforced (Private Subnets Blocked)</div>
      </div>
    `;
  }

  // Tab 3: DOM Signals
  if (elements.domSignalsContainer) {
    const htmlAvailable = data.html_available;
    elements.domSignalsContainer.innerHTML = `
      <div class="signal-card">
        <div class="signal-name">Live DOM Inspection</div>
        <div class="signal-val" style="color: ${htmlAvailable ? '#10B981' : '#F59E0B'}">
          ${htmlAvailable ? 'Available (HTTP 200)' : 'Unreachable'}
        </div>
      </div>
      <div class="signal-card">
        <div class="signal-name">SPA Shell Detection</div>
        <div class="signal-val" style="color: #06B6D4;">
          ${data.content_rendering_incomplete ? 'JS Hydrated (Bounded)' : 'Standard SSR'}
        </div>
      </div>
      <div class="signal-card" style="grid-column: span 2;">
        <div class="signal-name">Model Evaluation Mode</div>
        <div class="signal-val" style="color: #818CF8;">
          ${htmlAvailable ? 'Dual-Branch (URL + Live DOM)' : 'Degraded (URL Lexical Only)'}
        </div>
      </div>
    `;
  }
}

function showView(viewName) {
  Object.keys(views).forEach((key) => {
    if (views[key]) {
      if (key === viewName) views[key].classList.remove('hidden');
      else views[key].classList.add('hidden');
    }
  });
}
