import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  AlertTriangle, 
  Copy, 
  Check, 
  Clock, 
  Cpu, 
  ExternalLink, 
  RefreshCw,
  Info,
  Layers,
  AlertCircle,
  FileCode,
  Download,
  Lock,
  Globe,
  Share2
} from 'lucide-react';
import RiskBadge from './RiskBadge';
import IndicatorsList from './IndicatorsList';

export default function ResultCard({ result, onClear, onReScan }) {
  const [copied, setCopied] = useState(false);
  const [jsonExported, setJsonExported] = useState(false);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview', 'url_signals', 'domain_signals', 'dom_signals', 'json'

  if (!result) return null;

  const {
    url,
    status = 'safe',
    confidence = 0,
    risk_level = 'low',
    is_phishing = false,
    html_available = true,
    content_rendering_incomplete = false,
    detected_indicators = [],
    url_features_summary = {},
    error_message,
    analysis_timestamp,
    execution_time_ms = 0,
    risk_score = Math.round(confidence * 100),
    recommended_action = '',
    model_version = 'v1.2-xgboost-calibrated',
    signals_breakdown = {},
  } = result;

  const isError = status === 'error';
  const isPhish = status === 'phishing';
  const isSuspicious = status === 'suspicious';
  const isSafe = status === 'safe';

  const handleCopyUrl = () => {
    navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(result, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `phishguard_report_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    setJsonExported(true);
    setTimeout(() => setJsonExported(false), 2000);
  };

  // Card border and glow classes based on outcome
  let cardBorderGlow = 'border-emerald-500/40 glow-safe';
  let badgeTheme = 'text-emerald-400 border-emerald-500/30 bg-emerald-950/40';
  let gaugeColor = '#10B981';

  if (isPhish) {
    cardBorderGlow = 'border-rose-500/50 glow-danger';
    badgeTheme = 'text-rose-400 border-rose-500/30 bg-rose-950/40';
    gaugeColor = '#EF4444';
  } else if (isSuspicious) {
    cardBorderGlow = 'border-amber-500/50 glow-warn';
    badgeTheme = 'text-amber-400 border-amber-500/30 bg-amber-950/40';
    gaugeColor = '#F59E0B';
  } else if (isError) {
    cardBorderGlow = 'border-slate-700';
    badgeTheme = 'text-slate-400 border-slate-700 bg-slate-900';
    gaugeColor = '#64748B';
  }

  const normalizedScore = Math.max(0, Math.min(100, risk_score || Math.round(confidence * 100)));

  return (
    <div className="w-full max-w-4xl mx-auto my-8 animate-fadeIn">
      <div className={`glass-card rounded-3xl p-6 sm:p-8 border ${cardBorderGlow} transition-all duration-300 relative overflow-hidden shadow-2xl`}>
        
        {/* Top Header Row */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div>
            <div className="text-[11px] font-mono tracking-wider text-slate-400 uppercase mb-1.5 flex items-center gap-1.5">
              <span>Threat Assessment Report</span>
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              <span className="text-cyan-300 font-mono">{model_version}</span>
            </div>
            <RiskBadge status={status} riskLevel={risk_level} size="lg" />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleCopyUrl}
              className="px-3 py-1.5 rounded-xl border border-slate-700/80 bg-cyber-900/80 hover:bg-slate-800 text-xs font-mono text-slate-300 flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Copy analyzed URL"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy URL'}
            </button>

            <button
              onClick={handleExportJson}
              className="px-3 py-1.5 rounded-xl border border-slate-700/80 bg-cyber-900/80 hover:bg-slate-800 text-xs font-mono text-slate-300 flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Download forensic JSON telemetry report"
            >
              {jsonExported ? <Check className="w-3.5 h-3.5 text-cyan-400" /> : <Download className="w-3.5 h-3.5" />}
              {jsonExported ? 'Downloaded' : 'Export JSON'}
            </button>

            {onClear && (
              <button
                onClick={onClear}
                className="px-3 py-1.5 rounded-xl border border-slate-700/80 bg-cyber-900/80 hover:bg-slate-800 text-xs font-mono text-slate-300 flex items-center gap-1.5 transition-colors cursor-pointer"
                title="Scan another URL"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Reset</span>
              </button>
            )}
          </div>
        </div>

        {/* Target URL Display Bar */}
        <div className="my-5 p-3.5 rounded-2xl bg-cyber-950/80 border border-slate-800 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 min-w-0">
            <Globe className="w-4 h-4 text-cyan-400 shrink-0" />
            <span className="text-xs sm:text-sm font-mono text-slate-200 truncate select-all">
              {url}
            </span>
          </div>
          <a
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 shrink-0 px-2 py-1 rounded bg-cyan-950/40 border border-cyan-500/20"
          >
            <span>Visit</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>

        {/* Recommendation Callout Banner */}
        {recommended_action && (
          <div className={`p-4 rounded-2xl border mb-6 flex items-start gap-3 ${badgeTheme}`}>
            {isPhish ? (
              <ShieldX className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            ) : isSuspicious ? (
              <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            ) : (
              <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            )}
            <div>
              <div className="text-[10px] font-mono uppercase font-bold tracking-wider opacity-80 mb-0.5">
                Recommended Action
              </div>
              <p className="text-xs sm:text-sm font-medium leading-relaxed">
                {recommended_action}
              </p>
            </div>
          </div>
        )}

        {/* Main Verdict & Gauge Metrics Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-6">
          
          {/* Circular Risk Score Gauge */}
          <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col items-center justify-center text-center">
            <div className="relative w-28 h-28 flex items-center justify-center mb-3">
              <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-slate-800"
                  strokeWidth="3.2"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  strokeDasharray={`${normalizedScore}, 100`}
                  strokeWidth="3.2"
                  strokeLinecap="round"
                  stroke={gaugeColor}
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute flex flex-col items-center">
                <span className="text-2xl font-mono font-extrabold text-white tracking-tight">
                  {normalizedScore}%
                </span>
                <span className="text-[9px] font-mono uppercase text-slate-400">Risk Score</span>
              </div>
            </div>

            <div className="text-xs font-semibold text-slate-200">
              {isSafe ? 'Low Threat Probability' : isSuspicious ? 'Medium Threat Probability' : 'Critical Phishing Risk'}
            </div>
          </div>

          {/* Model Telemetry Card */}
          <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col justify-between">
            <div>
              <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-2 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-indigo-400" />
                <span>ML Model Inference</span>
              </div>
              <div className="text-sm font-semibold text-white mb-1">
                Calibrated XGBoost Ensemble
              </div>
              <p className="text-xs text-slate-400 leading-relaxed mb-3">
                Stratified 43-feature vector mapped via bounded sigmoid thresholds.
              </p>
            </div>

            <div className="space-y-1 text-[11px] font-mono text-slate-300 border-t border-slate-800 pt-2.5">
              <div className="flex justify-between">
                <span className="text-slate-500">Execution Latency:</span>
                <span>{execution_time_ms} ms</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Probability:</span>
                <span>{(confidence * 100).toFixed(1)}%</span>
              </div>
            </div>
          </div>

          {/* Content Inspection Status Card */}
          <div className="glass-panel p-5 rounded-2xl border border-slate-800/80 flex flex-col justify-between">
            <div>
              <div className="text-[10px] font-mono uppercase text-slate-400 tracking-wider mb-2 flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                <span>Inspection Coverage</span>
              </div>
              <div className="text-sm font-semibold text-white mb-1">
                {html_available ? 'Full Dual-Branch (URL + DOM)' : 'Degraded (URL Lexical Only)'}
              </div>
              <p className="text-xs text-slate-400 leading-relaxed mb-3">
                {html_available
                  ? 'Live HTML content inspected with strict SSRF bounds and timeout limits.'
                  : 'Live DOM unreachable; bounded heuristic fallback applied.'}
              </p>
            </div>

            <div className="space-y-1 text-[11px] font-mono text-slate-300 border-t border-slate-800 pt-2.5">
              <div className="flex justify-between">
                <span className="text-slate-500">SSRF Guard:</span>
                <span className="text-emerald-400">Enforced</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">SPA Shell Guard:</span>
                <span>{content_rendering_incomplete ? 'Active (Bounded)' : 'Standard'}</span>
              </div>
            </div>
          </div>

        </div>

        {/* Tabbed Forensic Deep-Dive Section */}
        <div className="mt-6 border-t border-slate-800 pt-6">
          
          {/* Navigation Tabs */}
          <div className="flex flex-wrap items-center gap-2 mb-4 border-b border-slate-800/80 pb-3">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-mono font-medium transition-all cursor-pointer ${
                activeTab === 'overview'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Detected Indicators ({detected_indicators.length})
            </button>
            <button
              onClick={() => setActiveTab('url_signals')}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-mono font-medium transition-all cursor-pointer ${
                activeTab === 'url_signals'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              URL Lexical Signals
            </button>
            <button
              onClick={() => setActiveTab('domain_signals')}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-mono font-medium transition-all cursor-pointer ${
                activeTab === 'domain_signals'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Domain & SSRF
            </button>
            <button
              onClick={() => setActiveTab('dom_signals')}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-mono font-medium transition-all cursor-pointer ${
                activeTab === 'dom_signals'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              DOM & Forms
            </button>
          </div>

          {/* Tab 1: Detected Indicators List */}
          {activeTab === 'overview' && (
            <div className="space-y-3">
              <IndicatorsList indicators={detected_indicators} isPhishing={is_phishing} />
            </div>
          )}

          {/* Tab 2: URL Lexical Signals */}
          {activeTab === 'url_signals' && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[10px] font-mono text-slate-500 uppercase">HTTPS Protocol</div>
                <div className="text-sm font-mono font-bold text-white mt-1">
                  {url_features_summary.uses_https ? (
                    <span className="text-emerald-400">Yes (TLS Encrypted)</span>
                  ) : (
                    <span className="text-rose-400">No (Plain HTTP)</span>
                  )}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[10px] font-mono text-slate-500 uppercase">Domain Length</div>
                <div className="text-sm font-mono font-bold text-white mt-1">
                  {url_features_summary.domain_length || 0} chars
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[10px] font-mono text-slate-500 uppercase">Subdomain Depth</div>
                <div className="text-sm font-mono font-bold text-white mt-1">
                  {url_features_summary.num_subdomains || 0} levels
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[10px] font-mono text-slate-500 uppercase">Suspicious Keywords</div>
                <div className="text-sm font-mono font-bold text-white mt-1">
                  {url_features_summary.has_suspicious_keywords ? (
                    <span className="text-rose-400">Detected (auth/login)</span>
                  ) : (
                    <span className="text-emerald-400">None</span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Tab 3: Domain & SSRF Signals */}
          {activeTab === 'domain_signals' && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[10px] font-mono text-slate-500 uppercase">IP Host Presence</div>
                <div className="text-sm font-mono font-bold text-white mt-1">
                  {url_features_summary.has_ip_address ? (
                    <span className="text-rose-400">Yes (Raw IP Used)</span>
                  ) : (
                    <span className="text-emerald-400">No (Standard Domain)</span>
                  )}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[10px] font-mono text-slate-500 uppercase">TLD Classification</div>
                <div className="text-sm font-mono font-bold text-white mt-1">
                  {url_features_summary.has_suspicious_tld ? (
                    <span className="text-rose-400">High-Risk TLD</span>
                  ) : (
                    <span className="text-emerald-400">Standard TLD</span>
                  )}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[10px] font-mono text-slate-500 uppercase">SSRF Perimeter Guard</div>
                <div className="text-sm font-mono font-bold text-emerald-400 mt-1">
                  Private Subnets Blocked
                </div>
              </div>
            </div>
          )}

          {/* Tab 4: DOM & Form Signals */}
          {activeTab === 'dom_signals' && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[10px] font-mono text-slate-500 uppercase">Live DOM Fetch</div>
                <div className="text-sm font-mono font-bold text-white mt-1">
                  {html_available ? (
                    <span className="text-emerald-400">Available (HTTP 200)</span>
                  ) : (
                    <span className="text-amber-400">Unreachable / Blocked</span>
                  )}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[10px] font-mono text-slate-500 uppercase">SPA Client-Rendered Shell</div>
                <div className="text-sm font-mono font-bold text-white mt-1">
                  {content_rendering_incomplete ? (
                    <span className="text-cyan-400">Yes (JS Hydration Bounded)</span>
                  ) : (
                    <span className="text-slate-300">Standard SSR</span>
                  )}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-[10px] font-mono text-slate-500 uppercase">Inspection Timestamp</div>
                <div className="text-xs font-mono text-slate-300 mt-1">
                  {analysis_timestamp || new Date().toISOString()}
                </div>
              </div>
            </div>
          )}

        </div>

      </div>
    </div>
  );
}
