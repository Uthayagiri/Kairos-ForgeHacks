import React from 'react';
import { WifiOff, AlertTriangle, ShieldX, RefreshCw, Server, HelpCircle } from 'lucide-react';

export default function ErrorState({ error, onRetry, onClear }) {
  if (!error) return null;

  const { errorType = 'ERROR', message } = error;
  const isNetwork = errorType === 'NETWORK_ERROR';
  const isTimeout = errorType === 'TIMEOUT_ERROR';
  const isValidation = errorType === 'VALIDATION_ERROR' || errorType === 'CLIENT_VALIDATION';

  return (
    <div className="w-full max-w-2xl mx-auto my-8 animate-fadeIn">
      <div className="glass-card rounded-2xl p-6 sm:p-8 border border-rose-500/40 glow-danger relative overflow-hidden text-center">
        
        {/* Icon */}
        <div className="mx-auto w-16 h-16 rounded-2xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 mb-4 shadow-lg shadow-rose-500/20">
          {isNetwork ? (
            <WifiOff className="w-8 h-8" />
          ) : isTimeout ? (
            <Server className="w-8 h-8" />
          ) : isValidation ? (
            <AlertTriangle className="w-8 h-8" />
          ) : (
            <ShieldX className="w-8 h-8" />
          )}
        </div>

        {/* Title */}
        <h3 className="text-lg sm:text-xl font-display font-bold text-white mb-2">
          {isNetwork
            ? 'Detection Service Unreachable'
            : isTimeout
            ? 'Scan Request Timed Out'
            : isValidation
            ? 'Invalid URL Input'
            : 'Analysis Request Failed'}
        </h3>

        {/* Message */}
        <p className="text-xs sm:text-sm text-slate-300 max-w-md mx-auto mb-6 leading-relaxed">
          {message || 'An error occurred while connecting to the detection service.'}
        </p>

        {/* Diagnostic Guide for Network Errors */}
        {isNetwork && (
          <div className="p-3.5 rounded-xl bg-cyber-950/90 border border-slate-800 text-left text-xs font-mono text-slate-400 mb-6 max-w-lg mx-auto">
            <div className="text-slate-300 font-semibold mb-1 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-cyan-400" />
              Troubleshooting Step:
            </div>
            <p className="text-[11px] leading-relaxed">
              Ensure the FastAPI backend server is running in the backend directory:
            </p>
            <div className="mt-1.5 p-2 rounded bg-black/40 text-cyan-300 select-all">
              uvicorn app.main:app --reload --port 8000
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex items-center justify-center gap-3">
          {onRetry && (
            <button
              onClick={onRetry}
              className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white text-xs font-medium flex items-center gap-1.5 transition-all shadow-md"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Retry Scan
            </button>
          )}
          <button
            onClick={onClear}
            className="px-4 py-2 rounded-xl border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
          >
            Dismiss
          </button>
        </div>

      </div>
    </div>
  );
}
