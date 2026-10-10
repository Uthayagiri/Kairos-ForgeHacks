import React from 'react';
import { Terminal, Shield, Sparkles, Activity, FileJson, Copy, Check } from 'lucide-react';
import ScanInput from '../components/ScanInput';
import ScanningState from '../components/ScanningState';
import ResultCard from '../components/ResultCard';
import ErrorState from '../components/ErrorState';

export default function ScannerPage({ scanManager }) {
  const {
    isScanning,
    currentResult,
    error,
    scannedUrl,
    runScan,
    clearCurrent,
  } = scanManager;

  return (
    <div className="w-full max-w-5xl mx-auto py-6 px-4 sm:px-6">
      
      {/* Header Banner */}
      <div className="text-center max-w-2xl mx-auto mb-8">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-3">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>Deep Forensic URL Scanner</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-display font-bold text-white tracking-tight">
          Interactive Cybersecurity Workbench
        </h1>
        <p className="text-xs sm:text-sm text-slate-300 mt-2 leading-relaxed">
          Inspect suspicious domains, analyze live DOM structure, and evaluate machine learning confidence in real time.
        </p>
      </div>

      {/* Main Scanner Input */}
      <ScanInput
        onScan={runScan}
        isScanning={isScanning}
        initialUrl={scannedUrl}
      />

      {/* Dynamic States */}
      <div className="mt-8">
        {isScanning && (
          <ScanningState targetUrl={scannedUrl} />
        )}

        {error && !isScanning && (
          <ErrorState
            error={error}
            onRetry={() => runScan(scannedUrl)}
            onClear={clearCurrent}
          />
        )}

        {currentResult && !isScanning && !error && (
          <ResultCard
            result={currentResult}
            onClear={clearCurrent}
            onReScan={() => runScan(scannedUrl)}
          />
        )}

        {/* Empty / Idle Guide when no scan has run */}
        {!isScanning && !currentResult && !error && (
          <div className="glass-panel rounded-3xl p-8 border border-slate-800 text-center max-w-3xl mx-auto my-12">
            <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center mx-auto mb-4">
              <Activity className="w-6 h-6" />
            </div>
            <h3 className="text-base font-semibold text-white mb-2 font-display">
              Ready to Inspect Web Resources
            </h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed mb-6">
              Paste any URL into the search bar above or choose one of the quick test presets to trigger multi-stage lexical, DOM, and ML evaluation.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-left">
              <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800">
                <div className="text-[11px] font-mono text-cyan-400 font-bold mb-1">Step 1</div>
                <div className="text-xs font-semibold text-slate-200">Input Validation</div>
                <div className="text-[11px] text-slate-400 mt-0.5">Defensive URL scheme and SSRF safety check.</div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800">
                <div className="text-[11px] font-mono text-indigo-400 font-bold mb-1">Step 2</div>
                <div className="text-xs font-semibold text-slate-200">Feature Extraction</div>
                <div className="text-[11px] text-slate-400 mt-0.5">43 lexical and live DOM heuristic signals computed.</div>
              </div>
              <div className="p-3.5 rounded-xl bg-slate-900/70 border border-slate-800">
                <div className="text-[11px] font-mono text-emerald-400 font-bold mb-1">Step 3</div>
                <div className="text-xs font-semibold text-slate-200">Model Classification</div>
                <div className="text-[11px] text-slate-400 mt-0.5">Tuned XGBoost scoring with bounded calibration.</div>
              </div>
            </div>
          </div>
        )}

      </div>

    </div>
  );
}
