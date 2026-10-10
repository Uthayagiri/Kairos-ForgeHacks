import { useState, useCallback, useEffect, useRef } from 'react';
import {
  predictUrl,
  checkBackendHealth,
  fetchHistory,
  clearBackendHistory,
  fetchStats,
  fetchModelInfo,
} from '../api/predictApi';

const STORAGE_KEY = 'phishguard_scan_history_v1';

// Preset sample URLs for quick testing and demonstration
export const SAMPLE_PRESETS = [
  {
    name: 'Legitimate Portal (Wikipedia)',
    url: 'https://en.wikipedia.org/wiki/Phishing',
    expected: 'safe',
    desc: 'Valid HTTPS, clean domain authority, authentic anchor link distribution.',
  },
  {
    name: 'Legitimate Platform (GitHub)',
    url: 'https://github.com/security',
    expected: 'safe',
    desc: 'High reputation domain, authentic authentication workflows, valid certificates.',
  },
  {
    name: 'Suspicious Homoglyph Simulation',
    url: 'http://paypa1-security-verification-alert.top/signin/auth.html',
    expected: 'suspicious',
    desc: 'Deceptive keyword clustering, uncommon TLD (.top), homoglyph typo (paypa1).',
  },
  {
    name: 'Malicious IP & Harvest Simulation',
    url: 'http://192.168.1.100/secure-banking/login.php',
    expected: 'phishing',
    desc: 'Raw IP address host, unencrypted HTTP, credential input fields on unverified endpoint.',
  },
  {
    name: 'Degraded / Unreachable Domain',
    url: 'http://nonexistent-phishguard-test-sample-889.xyz/portal',
    expected: 'degraded',
    desc: 'Offline domain triggering degraded-mode heuristic classification with bounded confidence.',
  },
];

// Curated demo dataset for dashboard initialization
export const DEMO_HISTORY_DATA = [
  {
    id: 'demo-1',
    url: 'https://www.google.com/search?q=cybersecurity',
    status: 'safe',
    risk_level: 'low',
    risk_score: 1.2,
    confidence: 0.012,
    timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    execution_time_ms: 112.4,
    html_available: true,
    result: {
      url: 'https://www.google.com/search?q=cybersecurity',
      status: 'safe',
      risk_level: 'low',
      risk_score: 1.2,
      confidence: 0.012,
      is_phishing: false,
      html_available: true,
      detected_indicators: [
        'Valid HTTPS TLS encryption established.',
        'Low lexical domain entropy (3.12).',
        'Standard reputable TLD (.com).',
      ],
      url_features_summary: {
        uses_https: true,
        domain_length: 14,
        path_length: 7,
        num_subdomains: 1,
        has_ip_address: false,
        has_suspicious_tld: false,
        has_suspicious_keywords: false,
      },
      recommended_action: 'SAFE TO PROCEED: Verified legitimate domain structure.',
      model_version: 'v1.2-xgboost-calibrated',
    },
  },
  {
    id: 'demo-2',
    url: 'http://account-update-alert-security-notice.xyz/login',
    status: 'phishing',
    risk_level: 'high',
    risk_score: 92.5,
    confidence: 0.925,
    timestamp: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
    execution_time_ms: 245.8,
    html_available: true,
    result: {
      url: 'http://account-update-alert-security-notice.xyz/login',
      status: 'phishing',
      risk_level: 'high',
      risk_score: 92.5,
      confidence: 0.925,
      is_phishing: true,
      html_available: true,
      detected_indicators: [
        'Multiple deceptive security keywords in domain string (account, update, alert, security).',
        'Unencrypted HTTP protocol used for authentication path.',
        'High-risk suspicious top-level domain (.xyz).',
        'Credential harvesting password input detected without legitimate origin match.',
      ],
      url_features_summary: {
        uses_https: false,
        domain_length: 42,
        path_length: 6,
        num_subdomains: 0,
        has_ip_address: false,
        has_suspicious_tld: true,
        has_suspicious_keywords: true,
      },
      recommended_action: 'CRITICAL THREAT: Do NOT enter credentials. Immediately avoid or block.',
      model_version: 'v1.2-xgboost-calibrated',
    },
  },
  {
    id: 'demo-3',
    url: 'http://paypa1-security-verify.top/auth',
    status: 'suspicious',
    risk_level: 'medium',
    risk_score: 64.0,
    confidence: 0.64,
    timestamp: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
    execution_time_ms: 310.2,
    html_available: false,
    result: {
      url: 'http://paypa1-security-verify.top/auth',
      status: 'suspicious',
      risk_level: 'medium',
      risk_score: 64.0,
      confidence: 0.64,
      is_phishing: false,
      html_available: false,
      detected_indicators: [
        'Homoglyph brand spoofing pattern detected (paypa1 instead of paypal).',
        'Uncommon suspicious TLD (.top).',
        'Live host unreachable; bounded degraded-mode evaluation applied.',
      ],
      url_features_summary: {
        uses_https: false,
        domain_length: 26,
        path_length: 5,
        num_subdomains: 0,
        has_ip_address: false,
        has_suspicious_tld: true,
        has_suspicious_keywords: true,
      },
      recommended_action: 'EXERCISE CAUTION: Brand typosquatting detected. Verify authenticity.',
      model_version: 'v1.2-xgboost-calibrated',
    },
  },
];

export function useScan() {
  const [isScanning, setIsScanning] = useState(false);
  const [currentResult, setCurrentResult] = useState(null);
  const [error, setError] = useState(null);
  const [scanHistory, setScanHistory] = useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) return parsed;
      }
    } catch {
      // ignore
    }
    return DEMO_HISTORY_DATA;
  });
  const [backendStatus, setBackendStatus] = useState({
    isOnline: null,
    latencyMs: null,
    modelInfo: null,
  });
  const [scannedUrl, setScannedUrl] = useState('');
  const [scanStep, setScanStep] = useState(0);

  const inFlightRef = useRef(false);
  const isMountedRef = useRef(true);

  // Sync scan history to localStorage
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(scanHistory));
    } catch {
      // storage quota
    }
  }, [scanHistory]);

  // Periodic health check
  const pingBackend = useCallback(async () => {
    const health = await checkBackendHealth();
    let modelData = null;
    if (health.isOnline) {
      modelData = await fetchModelInfo();
    }
    if (isMountedRef.current) {
      setBackendStatus({
        isOnline: health.isOnline,
        latencyMs: health.latencyMs || null,
        modelInfo: modelData,
      });
    }
  }, []);

  useEffect(() => {
    isMountedRef.current = true;
    pingBackend();
    const interval = setInterval(pingBackend, 15000);
    return () => {
      isMountedRef.current = false;
      clearInterval(interval);
    };
  }, [pingBackend]);

  const runScan = useCallback(async (url) => {
    if (inFlightRef.current) return;

    if (!url || !url.trim()) {
      setError({
        errorType: 'CLIENT_VALIDATION',
        message: 'Please enter a valid website URL to analyze (e.g. https://example.com).',
      });
      return;
    }

    inFlightRef.current = true;
    setIsScanning(true);
    setScanStep(1);
    setError(null);
    setScannedUrl(url.trim());

    // Step simulation for animated radar scanner
    const stepTimer1 = setTimeout(() => setScanStep(2), 350);
    const stepTimer2 = setTimeout(() => setScanStep(3), 700);
    const stepTimer3 = setTimeout(() => setScanStep(4), 1100);

    try {
      const response = await predictUrl(url.trim());

      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      clearTimeout(stepTimer3);

      if (!isMountedRef.current) return;

      if (!response.ok) {
        setError({
          errorType: response.errorType || 'ERROR',
          message: response.message || 'Failed to complete phishing analysis.',
        });
        setCurrentResult(null);
      } else {
        const data = response.data;
        setCurrentResult(data);

        // Record in session history
        if (data && data.status && data.status !== 'error') {
          const historyEntry = {
            id: `scan_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
            url: data.url || url.trim(),
            status: data.status,
            risk_level: data.risk_level,
            risk_score: data.risk_score !== undefined ? data.risk_score : Math.round((data.confidence || 0) * 100),
            confidence: data.confidence,
            timestamp: data.analysis_timestamp || new Date().toISOString(),
            execution_time_ms: data.execution_time_ms || 120.0,
            html_available: data.html_available,
            result: data,
          };

          setScanHistory((prev) => [historyEntry, ...prev.filter((p) => p.url !== historyEntry.url).slice(0, 49)]);
        }
      }
    } catch (err) {
      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      clearTimeout(stepTimer3);

      if (!isMountedRef.current) return;
      setError({
        errorType: 'UNEXPECTED_ERROR',
        message: err.message || 'An unexpected client error occurred while executing the scan.',
      });
      setCurrentResult(null);
    } finally {
      inFlightRef.current = false;
      if (isMountedRef.current) {
        setIsScanning(false);
        setScanStep(0);
      }
    }
  }, []);

  const selectHistoryItem = useCallback((item) => {
    if (item && item.result) {
      setCurrentResult(item.result);
      setScannedUrl(item.url);
      setError(null);
    }
  }, []);

  const deleteHistoryItem = useCallback((id) => {
    setScanHistory((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const clearCurrent = useCallback(() => {
    setCurrentResult(null);
    setError(null);
    setScannedUrl('');
  }, []);

  const clearHistory = useCallback(async () => {
    setScanHistory([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
      await clearBackendHistory();
    } catch {
      // ignore
    }
  }, []);

  const populateDemoData = useCallback(() => {
    setScanHistory(DEMO_HISTORY_DATA);
  }, []);

  return {
    isScanning,
    scanStep,
    currentResult,
    error,
    scanHistory,
    backendOnline: backendStatus.isOnline,
    backendLatency: backendStatus.latencyMs,
    modelInfo: backendStatus.modelInfo,
    scannedUrl,
    runScan,
    selectHistoryItem,
    deleteHistoryItem,
    clearCurrent,
    clearHistory,
    populateDemoData,
    pingBackend,
  };
}
