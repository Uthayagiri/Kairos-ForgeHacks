import React, { useState, useMemo } from 'react';
import { 
  BarChart3, 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  Search, 
  Trash2, 
  RefreshCw, 
  ExternalLink, 
  Layers, 
  Activity, 
  Clock, 
  Cpu, 
  Eye, 
  Check, 
  X, 
  Sparkles, 
  Download,
  AlertTriangle,
  Globe
} from 'lucide-react';
import RiskBadge from '../components/RiskBadge';

export default function DashboardPage({ scanManager, onNavigateToScanner }) {
  const {
    scanHistory = [],
    clearHistory,
    deleteHistoryItem,
    runScan,
    selectHistoryItem,
    populateDemoData,
    backendOnline,
    backendLatency,
  } = scanManager;

  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all'); // 'all', 'safe', 'suspicious', 'phishing'
  const [selectedScanDetail, setSelectedScanDetail] = useState(null);
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  // Compute aggregated KPI metrics
  const stats = useMemo(() => {
    const total = scanHistory.length;
    const safeCount = scanHistory.filter((i) => i.status === 'safe').length;
    const suspiciousCount = scanHistory.filter((i) => i.status === 'suspicious').length;
    const phishingCount = scanHistory.filter((i) => i.status === 'phishing').length;

    const safePct = total > 0 ? Math.round((safeCount / total) * 100) : 0;
    const suspiciousPct = total > 0 ? Math.round((suspiciousCount / total) * 100) : 0;
    const phishingPct = total > 0 ? Math.round((phishingCount / total) * 100) : 0;

    const avgLatency =
      total > 0
        ? Math.round(
            scanHistory.reduce((acc, curr) => acc + (curr.execution_time_ms || 120), 0) / total
          )
        : 0;

    return {
      total,
      safeCount,
      suspiciousCount,
      phishingCount,
      safePct,
      suspiciousPct,
      phishingPct,
      avgLatency,
    };
  }, [scanHistory]);

  // Filter scan history based on search query and status filter
  const filteredHistory = useMemo(() => {
    return scanHistory.filter((item) => {
      const matchesSearch =
        !searchQuery ||
        item.url.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (item.result?.detected_indicators || []).some((ind) =>
          ind.toLowerCase().includes(searchQuery.toLowerCase())
        );

      const matchesStatus = statusFilter === 'all' || item.status === statusFilter;

      return matchesSearch && matchesStatus;
    });
  }, [scanHistory, searchQuery, statusFilter]);

  const handleInspect = (item) => {
    setSelectedScanDetail(item);
  };

  const handleReScan = (url) => {
    if (onNavigateToScanner) {
      onNavigateToScanner(url);
    } else {
      runScan(url);
    }
  };

  return (
    <div className="w-full max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8 space-y-8 animate-fadeIn">
      
      {/* Top Header Row */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-2">
            <BarChart3 className="w-3.5 h-3.5 text-cyan-400" />
            <span>Security Operations Telemetry</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-display font-bold text-white tracking-tight">
            Threat Intelligence & Scan History
          </h1>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {scanHistory.length === 0 && (
            <button
              onClick={populateDemoData}
              className="px-3.5 py-2 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-xs font-mono text-cyan-300 transition-all flex items-center gap-1.5 cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Load Demo Telemetry</span>
            </button>
          )}

          {scanHistory.length > 0 && (
            <button
              onClick={() => setShowClearConfirm(true)}
              className="px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-rose-950/40 border border-slate-700/80 hover:border-rose-500/40 text-xs font-mono text-slate-300 hover:text-rose-300 transition-all flex items-center gap-1.5 cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear History</span>
            </button>
          )}
        </div>
      </div>

      {/* KPI Stats Cards Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Card 1: Total Scans */}
        <div className="glass-card p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Total Evaluated</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-mono font-bold text-white">
            {stats.total}
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">
            {backendOnline ? 'Live ML Backend Connected' : 'Offline / Local Session'}
          </div>
        </div>

        {/* Card 2: Safe Rate */}
        <div className="glass-card p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Legitimate</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-mono font-bold text-emerald-400">
            {stats.safeCount} <span className="text-sm font-normal text-slate-400">({stats.safePct}%)</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">
            Verified Clean Heuristics
          </div>
        </div>

        {/* Card 3: Suspicious Rate */}
        <div className="glass-card p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Suspicious</span>
            <ShieldAlert className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-mono font-bold text-amber-400">
            {stats.suspiciousCount} <span className="text-sm font-normal text-slate-400">({stats.suspiciousPct}%)</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">
            Anomalous / Degraded Modes
          </div>
        </div>

        {/* Card 4: Phishing Threats */}
        <div className="glass-card p-5 rounded-2xl border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Threats Blocked</span>
            <ShieldX className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-mono font-bold text-rose-400">
            {stats.phishingCount} <span className="text-sm font-normal text-slate-400">({stats.phishingPct}%)</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1 font-mono">
            High-Risk Phishing Hazards
          </div>
        </div>

      </div>

      {/* Visual Threat Distribution Bar */}
      {stats.total > 0 && (
        <div className="glass-card p-6 rounded-2xl border border-slate-800">
          <div className="flex items-center justify-between mb-3">
            <div className="text-xs font-mono font-semibold uppercase text-slate-300">
              Risk Distribution Breakdown
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> Safe ({stats.safePct}%)
              </span>
              <span className="flex items-center gap-1.5 text-amber-400">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> Suspicious ({stats.suspiciousPct}%)
              </span>
              <span className="flex items-center gap-1.5 text-rose-400">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500" /> Phishing ({stats.phishingPct}%)
              </span>
            </div>
          </div>

          {/* Multi-segment progress bar */}
          <div className="w-full h-3.5 rounded-full bg-slate-900 overflow-hidden flex p-0.5 border border-slate-800">
            {stats.safePct > 0 && (
              <div
                style={{ width: `${stats.safePct}%` }}
                className="h-full bg-emerald-500 rounded-l-full transition-all duration-500"
                title={`Safe: ${stats.safeCount}`}
              />
            )}
            {stats.suspiciousPct > 0 && (
              <div
                style={{ width: `${stats.suspiciousPct}%` }}
                className="h-full bg-amber-500 transition-all duration-500"
                title={`Suspicious: ${stats.suspiciousCount}`}
              />
            )}
            {stats.phishingPct > 0 && (
              <div
                style={{ width: `${stats.phishingPct}%` }}
                className="h-full bg-rose-500 rounded-r-full transition-all duration-500"
                title={`Phishing: ${stats.phishingCount}`}
              />
            )}
          </div>
        </div>
      )}

      {/* Search & Filter Controls */}
      <div className="glass-card p-4 rounded-2xl border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
        
        {/* Search Bar */}
        <div className="relative w-full sm:w-80 flex items-center">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search domain, URL keyword, or signal..."
            className="w-full bg-slate-950/80 border border-slate-700/60 rounded-xl pl-9 pr-8 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400/60"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-2.5 text-slate-500 hover:text-slate-300"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Status Filter Buttons */}
        <div className="flex items-center gap-1.5 w-full sm:w-auto overflow-x-auto">
          {[
            { id: 'all', label: 'All Scans' },
            { id: 'safe', label: 'Safe' },
            { id: 'suspicious', label: 'Suspicious' },
            { id: 'phishing', label: 'Phishing' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setStatusFilter(tab.id)}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono transition-all cursor-pointer ${
                statusFilter === tab.id
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

      </div>

      {/* Historical Scans Table */}
      <div className="glass-card rounded-2xl border border-slate-800 overflow-hidden">
        
        {filteredHistory.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <Shield className="w-10 h-10 text-slate-600 mx-auto mb-3" />
            <h4 className="text-sm font-semibold text-slate-200 font-display">No Scan Records Found</h4>
            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
              {searchQuery || statusFilter !== 'all'
                ? 'No evaluations match the active filter criteria.'
                : 'Run a URL scan from the workbench to start tracking forensic telemetry.'}
            </p>
            {scanHistory.length === 0 && (
              <button
                onClick={populateDemoData}
                className="mt-4 px-4 py-2 rounded-xl bg-cyan-500/20 border border-cyan-500/40 text-xs font-mono text-cyan-300 hover:bg-cyan-500/30 transition-all cursor-pointer"
              >
                Load Demo Dataset
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-sans">
              <thead className="bg-slate-950/80 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Analyzed Target URL</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4 text-center">Risk Score</th>
                  <th className="py-3 px-4">DOM Status</th>
                  <th className="py-3 px-4">Latency</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredHistory.map((item) => {
                  const score = item.risk_score !== undefined ? item.risk_score : Math.round((item.confidence || 0) * 100);
                  const isSafe = item.status === 'safe';
                  const isSuspicious = item.status === 'suspicious';
                  const isPhish = item.status === 'phishing';

                  return (
                    <tr key={item.id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="py-3 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                        {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="py-3 px-4 text-slate-200 max-w-xs truncate" title={item.url}>
                        {item.url}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <RiskBadge status={item.status} riskLevel={item.risk_level} size="sm" />
                      </td>
                      <td className="py-3 px-4 text-center whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                          isSafe
                            ? 'bg-emerald-950/40 text-emerald-300 border border-emerald-500/20'
                            : isSuspicious
                            ? 'bg-amber-950/40 text-amber-300 border border-amber-500/20'
                            : 'bg-rose-950/40 text-rose-300 border border-rose-500/20'
                        }`}>
                          {score}%
                        </span>
                      </td>
                      <td className="py-3 px-4 text-[11px] text-slate-400 whitespace-nowrap">
                        {item.html_available ? (
                          <span className="text-emerald-400">Live DOM</span>
                        ) : (
                          <span className="text-amber-400">URL Only</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-[11px] text-slate-400 whitespace-nowrap">
                        {item.execution_time_ms ? `${item.execution_time_ms} ms` : '120 ms'}
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => handleInspect(item)}
                            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 transition-colors"
                            title="Inspect full forensic report"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleReScan(item.url)}
                            className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-indigo-300 transition-colors"
                            title="Re-run analysis in workbench"
                          >
                            <RefreshCw className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => deleteHistoryItem(item.id)}
                            className="p-1.5 rounded-lg bg-slate-900 hover:bg-rose-950/50 text-slate-400 hover:text-rose-400 transition-colors"
                            title="Delete entry"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

      </div>

      {/* Detail Forensic Modal */}
      {selectedScanDetail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
          <div className="relative w-full max-w-2xl glass-card rounded-3xl p-6 border border-cyan-500/30 shadow-2xl overflow-y-auto max-h-[85vh]">
            
            <button
              onClick={() => setSelectedScanDetail(null)}
              className="absolute top-5 right-5 p-2 rounded-xl bg-slate-900 border border-slate-700 text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-2 mb-4">
              <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-white font-display">Forensic Evaluation Detail</h3>
                <span className="text-xs text-slate-400 font-mono">Scan ID: {selectedScanDetail.id}</span>
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 break-all mb-4">
              {selectedScanDetail.url}
            </div>

            <div className="flex items-center justify-between mb-4">
              <RiskBadge status={selectedScanDetail.status} riskLevel={selectedScanDetail.risk_level} size="md" />
              <span className="text-xs font-mono text-slate-400">
                Score: <strong className="text-white">{selectedScanDetail.risk_score}%</strong> • Latency: {selectedScanDetail.execution_time_ms}ms
              </span>
            </div>

            {selectedScanDetail.result?.recommended_action && (
              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-300 mb-4">
                <span className="font-bold text-cyan-300 uppercase font-mono text-[10px] block mb-1">
                  Recommendation
                </span>
                {selectedScanDetail.result.recommended_action}
              </div>
            )}

            <div className="space-y-2 mb-6">
              <div className="text-xs font-mono uppercase text-slate-400 font-bold">Detected Indicators</div>
              {(selectedScanDetail.result?.detected_indicators || []).map((ind, i) => (
                <div key={i} className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-300">
                  {ind}
                </div>
              ))}
            </div>

            <div className="flex justify-end gap-2">
              <button
                onClick={() => {
                  setSelectedScanDetail(null);
                  handleReScan(selectedScanDetail.url);
                }}
                className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-mono font-bold transition-all cursor-pointer"
              >
                Inspect in Workbench
              </button>
              <button
                onClick={() => setSelectedScanDetail(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition-all cursor-pointer"
              >
                Close
              </button>
            </div>

          </div>
        </div>
      )}

      {/* Clear Confirmation Modal */}
      {showClearConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
          <div className="relative w-full max-w-md glass-card rounded-3xl p-6 border border-rose-500/40 shadow-2xl text-center">
            <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-center mx-auto mb-4">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-white font-display mb-2">Clear All Scan History?</h3>
            <p className="text-xs text-slate-400 mb-6 leading-relaxed">
              This action will permanently delete all {scanHistory.length} scan records from local browser memory and backend session cache.
            </p>
            <div className="flex items-center justify-center gap-3">
              <button
                onClick={() => {
                  clearHistory();
                  setShowClearConfirm(false);
                }}
                className="px-4 py-2.5 rounded-xl bg-rose-500 hover:bg-rose-600 text-white text-xs font-mono font-bold transition-all cursor-pointer"
              >
                Yes, Clear All
              </button>
              <button
                onClick={() => setShowClearConfirm(false)}
                className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition-all cursor-pointer"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
