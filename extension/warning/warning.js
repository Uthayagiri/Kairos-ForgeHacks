/**
 * PhishGuard AI Warning Interstitial Controller
 *
 * Safely parses forensic indicators, renders human-readable threat rationale
 * using strict textContent (XSS-safe), handles "Return to Safety", and coordinates
 * user override permissions with the background service worker.
 */

document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const rawTargetUrl = urlParams.get('url') || 'Unknown Destination';
  const riskScore = urlParams.get('risk') || '85';
  const status = urlParams.get('status') || 'phishing';
  const rawThreats = urlParams.get('reasons');
  const rawSignals = urlParams.get('signals');

  // Validate target URL scheme to prevent javascript: or data: injection
  let safeTargetUrl = rawTargetUrl;
  const isWebUrl = safeTargetUrl.startsWith('http://') || safeTargetUrl.startsWith('https://');
  if (!isWebUrl && safeTargetUrl !== 'Unknown Destination') {
    safeTargetUrl = 'Invalid or Potentially Malicious Protocol';
  }

  // 1. Populate Intercepted Destination safely
  const targetEl = document.getElementById('target-url');
  if (targetEl) {
    targetEl.textContent = safeTargetUrl;
  }

  // 2. Populate Risk Score & Category Badges
  const scoreEl = document.getElementById('risk-score-value');
  if (scoreEl) {
    scoreEl.textContent = `${riskScore}%`;
  }

  const badgeEl = document.getElementById('risk-badge');
  if (badgeEl) {
    const numericScore = parseFloat(riskScore) || 0;
    if (numericScore >= 70 || status === 'phishing') {
      badgeEl.textContent = 'CRITICAL PHISHING THREAT';
      badgeEl.className = 'risk-badge risk-badge-high';
    } else if (numericScore >= 30 || status === 'suspicious') {
      badgeEl.textContent = 'SUSPICIOUS ACTIVITY';
      badgeEl.className = 'risk-badge risk-badge-medium';
    } else {
      badgeEl.textContent = 'SECURITY ALERT';
      badgeEl.className = 'risk-badge risk-badge-medium';
    }
  }

  // 3. Populate Threat Indicators safely using textContent
  const listEl = document.getElementById('threat-list');
  if (listEl) {
    let threats = [];
    if (rawThreats) {
      try {
        threats = JSON.parse(rawThreats);
      } catch {
        threats = [];
      }
    }

    if (Array.isArray(threats) && threats.length > 0) {
      listEl.innerHTML = '';
      threats.forEach((reason) => {
        if (typeof reason === 'string' && reason.trim()) {
          const li = document.createElement('li');
          li.textContent = reason.trim();
          listEl.appendChild(li);
        }
      });
    } else {
      listEl.innerHTML = '';
      const defaultLi = document.createElement('li');
      defaultLi.textContent = 'Severe phishing characteristics identified by XGBoost machine learning model.';
      listEl.appendChild(defaultLi);
    }
  }

  // 4. Populate Forensic Signals Breakdown if available
  if (rawSignals) {
    try {
      const signals = JSON.parse(rawSignals);
      const breakdownBox = document.getElementById('signals-breakdown-box');
      const breakdownGrid = document.getElementById('breakdown-content');

      if (breakdownBox && breakdownGrid && typeof signals === 'object') {
        const urlSigs = signals.url_signals || {};
        const domainSigs = signals.domain_ssrf || {};
        const domSigs = signals.dom_form_signals || {};

        const hasAnySignals =
          Object.keys(urlSigs).length > 0 ||
          Object.keys(domainSigs).length > 0 ||
          Object.keys(domSigs).length > 0;

        if (hasAnySignals) {
          breakdownGrid.innerHTML = '';

          // URL Signals Card
          if (Object.keys(urlSigs).length > 0) {
            const card = document.createElement('div');
            card.className = 'breakdown-card';
            const title = document.createElement('div');
            title.className = 'breakdown-card-title';
            title.textContent = 'URL Structure';
            card.appendChild(title);

            appendSignalRow(card, 'HTTPS Encrypted', urlSigs.uses_https ? 'Yes' : 'No', !urlSigs.uses_https);
            if (urlSigs.has_ip_address) appendSignalRow(card, 'Raw IP Host', 'Detected', true);
            if (urlSigs.num_subdomains >= 3) appendSignalRow(card, 'Subdomains', urlSigs.num_subdomains, true);
            if (urlSigs.has_suspicious_keywords) appendSignalRow(card, 'Auth Keywords', 'Detected', true);
            breakdownGrid.appendChild(card);
          }

          // Domain / SSRF Card
          if (Object.keys(domainSigs).length > 0) {
            const card = document.createElement('div');
            card.className = 'breakdown-card';
            const title = document.createElement('div');
            title.className = 'breakdown-card-title';
            title.textContent = 'Domain & Infrastructure';
            card.appendChild(title);

            if (domainSigs.has_suspicious_tld) appendSignalRow(card, 'High-Risk TLD', 'Detected', true);
            if (domainSigs.is_shortened_url) appendSignalRow(card, 'URL Shortener', 'Detected', true);
            if (domainSigs.ssrf_blocked) appendSignalRow(card, 'SSRF Restricted', 'Blocked', true);
            breakdownGrid.appendChild(card);
          }

          // DOM & Form Signals Card
          if (Object.keys(domSigs).length > 0) {
            const card = document.createElement('div');
            card.className = 'breakdown-card';
            const title = document.createElement('div');
            title.className = 'breakdown-card-title';
            title.textContent = 'Live DOM & Form Signals';
            card.appendChild(title);

            if (domSigs.has_login_form) appendSignalRow(card, 'Login Form', 'Detected', true);
            if (domSigs.num_password_fields > 0) appendSignalRow(card, 'Password Fields', domSigs.num_password_fields, true);
            if (domSigs.external_form_action) appendSignalRow(card, 'External Form Post', 'Detected', true);
            breakdownGrid.appendChild(card);
          }

          breakdownBox.classList.remove('hidden');
        }
      }
    } catch {
      // Signals parsing error - default hidden
    }
  }

  // 5. Action Handlers
  // Primary "Return to Safety" Button
  const safetyBtn = document.getElementById('safety-btn');
  if (safetyBtn) {
    safetyBtn.addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'https://www.google.com';
      }
    });
  }

  // Open Full Web Dashboard Button
  const dashboardBtn = document.getElementById('open-dashboard-btn');
  if (dashboardBtn) {
    dashboardBtn.addEventListener('click', () => {
      window.location.href = 'http://localhost:5173';
    });
  }

  // Override Toggle Panel
  const toggleBtn = document.getElementById('toggle-override-btn');
  const overridePanel = document.getElementById('override-panel');
  if (toggleBtn && overridePanel) {
    toggleBtn.addEventListener('click', () => {
      overridePanel.classList.toggle('hidden');
    });
  }

  // Proceed Anyway Override Button
  const proceedBtn = document.getElementById('proceed-override-btn');
  if (proceedBtn) {
    proceedBtn.addEventListener('click', () => {
      if (!isWebUrl) {
        alert('Cannot navigate to an invalid or unverified protocol.');
        return;
      }

      const confirmed = window.confirm(
        'SECURITY WARNING: Proceeding to this website may expose passwords, financial accounts, or private data to cyber attackers. Do you want to override protection?'
      );

      if (confirmed) {
        // Register override with background service worker to prevent infinite redirect loop
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
          chrome.runtime.sendMessage({ type: 'SET_OVERRIDE', url: safeTargetUrl }, () => {
            window.location.href = safeTargetUrl;
          });
        } else {
          window.location.href = safeTargetUrl;
        }
      }
    });
  }
});

function appendSignalRow(container, labelText, valueText, isFlag) {
  const row = document.createElement('div');
  row.className = 'breakdown-card-item';

  const label = document.createElement('span');
  label.textContent = labelText;

  const value = document.createElement('span');
  value.textContent = String(valueText);
  value.className = isFlag ? 'val-flag' : 'val-ok';

  row.appendChild(label);
  row.appendChild(value);
  container.appendChild(row);
}
