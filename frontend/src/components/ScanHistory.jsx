import React from 'react';
import { History, Trash2, ChevronRight, Clock, Globe } from 'lucide-react';
import RiskBadge from './RiskBadge';

export default function ScanHistory({ history = [], onSelect, onClear }) {
  if (!history || history.length === 0) {
    return null;
  }

  return (
    <div className="w-full max-w-4xl mx-auto my-10">
      <div className="glass-card rounded-2xl p-6 border border-slate-800">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-4 mb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-200">
              Session Scan History
            </h3>
            <span className="px-2 py-0.5 rounded-full text-[11px] font-mono bg-cyber-900 border border-slate-700 text-slate-300">
              {history.length} {history.length === 1 ? 'scan' : 'scans'}
            </span>
          </div>

          <button
            onClick={onClear}
            className="text-xs text-slate-400 hover:text-rose-400 flex items-center gap-1.5 transition-colors p-1"
            title="Clear in-memory session history"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear</span>
          </button>
        </div>

        {/* Scans List */}
        <div className="divide-y divide-slate-800/60 max-h-72 overflow-y-auto pr-1">
          {history.map((item) => (
            <div
              key={item.id}
              onClick={() => onSelect(item)}
              className="py-3 px-2 flex items-center justify-between gap-4 hover:bg-cyber-900/50 rounded-xl cursor-pointer transition-all duration-150 group"
            >
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <Globe className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 flex-shrink-0 transition-colors" />
                <div className="min-w-0 flex-1">
                  <div className="text-xs sm:text-sm font-mono text-slate-200 truncate group-hover:text-cyan-300 transition-colors">
                    {item.url}
                  </div>
                  <div className="flex items-center gap-3 text-[11px] text-slate-500 mt-0.5 font-mono">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(item.timestamp).toLocaleTimeString()}
                    </span>
                    <span>•</span>
                    <span>{(item.confidence * 100).toFixed(1)}% Threat Score</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-3 flex-shrink-0">
                <RiskBadge status={item.status} riskLevel={item.risk_level} size="sm" />
                <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all" />
              </div>
            </div>
          ))}
        </div>

        <div className="mt-3 pt-3 border-t border-slate-800/60 text-[11px] text-slate-500 text-center font-mono">
          * History is stored in memory for this session and resets on page reload.
        </div>

      </div>
    </div>
  );
}
