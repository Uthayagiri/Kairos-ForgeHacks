/**
 * Comprehensive API client module for the PhishGuard AI backend.
 * Handles HTTP requests to /api/analyze, /predict, /api/history, /api/stats,
 * and /health with defensive timeouts, network resilience, and detailed error mapping.
 */

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000').replace(/\/+$/, '');
const REQUEST_TIMEOUT_MS = 15000; // 15-second client-side timeout

/**
 * Check if the backend API service and ML model are operational.
 * @returns {Promise<{ isOnline: boolean, latencyMs?: number, modelInfo?: any, error?: string }>}
 */
export async function checkBackendHealth() {
  const startTime = performance.now();
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 4000);

  try {
    const response = await fetch(`${API_BASE_URL}/health`, {
      method: 'GET',
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    const latencyMs = Math.round(performance.now() - startTime);

    if (response.ok) {
      const data = await response.json();
      return { isOnline: data.status === 'ok', latencyMs };
    }
    return { isOnline: false, latencyMs, error: `HTTP ${response.status}` };
  } catch (err) {
    clearTimeout(timeoutId);
    return {
      isOnline: false,
      error: err.name === 'AbortError' ? 'Connection timed out' : 'Backend offline',
    };
  }
}

/**
 * Retrieve active ML model telemetry and SHA256 integrity metadata.
 */
export async function fetchModelInfo() {
  try {
    const response = await fetch(`${API_BASE_URL}/model/info`, {
      headers: { Accept: 'application/json' },
    });
    if (response.ok) {
      return await response.json();
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Send a URL to the detection engine for full phishing analysis.
 * @param {string} url Webpage URL to inspect
 * @returns {Promise<{ ok: boolean, data?: any, errorType?: string, message?: string }>}
 */
export async function predictUrl(url) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    // Try POST /api/analyze first, fallback to /predict if needed
    const response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    // Handle HTTP error statuses
    if (!response.ok) {
      if (response.status === 422) {
        return {
          ok: false,
          errorType: 'VALIDATION_ERROR',
          message: 'The URL was rejected by the server (invalid format, unsupported scheme, or exceeded 2,048 characters).',
        };
      }
      if (response.status === 500) {
        return {
          ok: false,
          errorType: 'SERVER_ERROR',
          message: 'The detection server encountered an internal error while evaluating the model.',
        };
      }
      return {
        ok: false,
        errorType: 'HTTP_ERROR',
        message: `Detection service returned HTTP status ${response.status}.`,
      };
    }

    // HTTP 200 OK: Response contains complete telemetry payload
    const result = await response.json();
    return {
      ok: true,
      data: result,
    };
  } catch (err) {
    clearTimeout(timeoutId);

    if (err.name === 'AbortError') {
      return {
        ok: false,
        errorType: 'TIMEOUT_ERROR',
        message: 'Analysis timed out after 15 seconds. The target website may be blocking requests or extremely slow.',
      };
    }

    return {
      ok: false,
      errorType: 'NETWORK_ERROR',
      message: `Cannot connect to the phishing detection backend at ${API_BASE_URL}. Ensure the FastAPI server is running on port 8000.`,
    };
  }
}

let cachedSessionToken = null;

/**
 * Retrieve active session authentication headers for history and stats operations.
 */
async function getSessionAuthHeaders() {
  const headers = {};
  const envKey = import.meta.env.VITE_HISTORY_API_KEY;
  if (envKey) {
    headers['X-API-Key'] = envKey;
    return headers;
  }

  if (cachedSessionToken) {
    headers['X-API-Key'] = cachedSessionToken;
    return headers;
  }

  try {
    const res = await fetch(`${API_BASE_URL}/api/auth/token`);
    if (res.ok) {
      const data = await res.json();
      if (data && data.token) {
        cachedSessionToken = data.token;
        headers['X-API-Key'] = cachedSessionToken;
      }
    }
  } catch {
    // Proceed if token acquisition fails; server will enforce requirement based on environment
  }

  return headers;
}

/**
 * Fetch scan history from the backend.
 * @param {number} limit Maximum number of records
 * @param {string} status Filter by risk status
 */
export async function fetchHistory(limit = 50, status = null) {
  try {
    const authHeaders = await getSessionAuthHeaders();
    let url = `${API_BASE_URL}/api/history?limit=${limit}`;
    if (status && status !== 'all') {
      url += `&status=${encodeURIComponent(status)}`;
    }
    const response = await fetch(url, { headers: authHeaders });
    if (response.ok) {
      return await response.json();
    }
    return [];
  } catch {
    return [];
  }
}

/**
 * Purge scan history records from the server session.
 */
export async function clearBackendHistory() {
  try {
    const authHeaders = await getSessionAuthHeaders();
    const response = await fetch(`${API_BASE_URL}/api/history/clear`, {
      method: 'POST',
      headers: authHeaders,
    });
    if (response.ok) {
      return await response.json();
    }
    return { status: 'error' };
  } catch (err) {
    return { status: 'error', error: err.message };
  }
}

/**
 * Fetch aggregate security telemetry statistics.
 */
export async function fetchStats() {
  try {
    const authHeaders = await getSessionAuthHeaders();
    const response = await fetch(`${API_BASE_URL}/api/stats`, {
      headers: authHeaders,
    });
    if (response.ok) {
      return await response.json();
    }
    return null;
  } catch {
    return null;
  }
}

