import React, { useState, useEffect } from 'react';
import { Search, Globe, ArrowRight, Sparkles, X, Clipboard, ShieldAlert, CheckCircle, HelpCircle } from 'lucide-react';

const PRESET_SAMPLES = [
  {
    label: 'Wikipedia (Safe)',
    url: 'https://en.wikipedia.org/wiki/Phishing',
    type: 'safe',
    desc: 'Verified legitimate portal with clean structural heuristics',
  },
  {
    label: 'GitHub (Safe)',
    url: 'https://github.com/security',
    expected: 'safe',
    type: 'safe',
    desc: 'High authority platform with valid TLS certification',
  },
  {
    label: 'PayPal Spoof (Suspicious)',
    url: 'http://paypa1-security-verification-alert.top/signin/auth.html',
    type: 'suspicious',
    desc: 'Homoglyph typo domain, suspicious .top TLD, credential keywords',
  },
  {
    label: 'Raw IP Harvest (Phishing)',
    url: 'http://192.168.1.100/secure-banking/login.php',
    type: 'phish',
    desc: 'Raw IP address host, unencrypted HTTP, login credential form',
  },
  {
    label: 'Offline / Degraded (Unknown)',
    url: 'http://nonexistent-phishguard-test-sample-889.xyz/portal',
    type: 'degraded',
    desc: 'Unreachable host triggering bounded degraded-mode evaluation',
  },
];

export default function ScanInput({ onScan, isScanning, initialUrl = '' }) {
  const [url, setUrl] = useState(initialUrl);

  useEffect(() => {
    if (initialUrl) {
      setUrl(initialUrl);
    }
  }, [initialUrl]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url && url.trim() && !isScanning) {
      onScan(url.trim());
    }
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setUrl(text.trim());
      }
    } catch {
      // clipboard permission denied
    }
  };

  const handleSelectPreset = (presetUrl) => {
    if (isScanning) return;
    setUrl(presetUrl);
    onScan(presetUrl);
  };

  return (
    <div className="w-full max-w-4xl mx-auto">
      
      {/* Input Form Card */}
      <form onSubmit={handleSubmit} className="relative group">
        <div className="glass-card rounded-2xl p-2.5 sm:p-3 transition-all duration-300 focus-within:border-cyan-500/60 focus-within:ring-2 focus-within:ring-cyan-500/20 glow-cyan">
          <div className="flex flex-col sm:flex-row items-center gap-2">
            
            {/* Input Field with Icons */}
            <div className="relative flex-1 w-full flex items-center">
              <div className="absolute left-3.5 text-cyan-400 pointer-events-none">
                <Globe className="w-5 h-5 opacity-80" />
              </div>
              
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter suspicious or legitimate URL (e.g. https://example.com)..."
                disabled={isScanning}
                maxLength={2048}
                className="w-full bg-cyber-950/70 border border-slate-700/60 rounded-xl pl-11 pr-20 py-3.5 text-sm sm:text-base font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400/60 transition-colors disabled:opacity-60"
              />

              {/* Action icons on right side of input */}
              <div className="absolute right-3 flex items-center gap-1">
                {navigator.clipboard && (
                  <button
                    type="button"
                    onClick={handlePaste}
                    disabled={isScanning}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-300 hover:bg-slate-800 transition-colors cursor-pointer"
                    title="Paste from clipboard"
                  >
                    <Clipboard className="w-4 h-4" />
                  </button>
                )}

                {url && !isScanning && (
                  <button
                    type="button"
                    onClick={() => setUrl('')}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
                    title="Clear input"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>

            {/* Scan Submit Button */}
            <button
              type="submit"
              disabled={!url.trim() || isScanning}
              className={`w-full sm:w-auto px-7 py-3.5 rounded-xl font-mono text-xs sm:text-sm font-bold flex items-center justify-center gap-2.5 transition-all duration-200 shadow-lg cursor-pointer ${
                !url.trim() || isScanning
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/40'
                  : 'bg-gradient-to-r from-cyan-500 via-sky-400 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 shadow-cyan-500/20 hover:shadow-cyan-500/40 hover:scale-[1.01] active:scale-[0.99] border border-cyan-300/40'
              }`}
            >
              {isScanning ? (
                <>
                  <div className="w-4 h-4 border-2 border-slate-900 border-t-transparent rounded-full animate-spin" />
                  <span>Inspecting...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 text-slate-950" />
                  <span>Analyze URL</span>
                  <ArrowRight className="w-4 h-4 text-slate-950 opacity-80" />
                </>
              )}
            </button>
          </div>
        </div>
      </form>

      {/* Quick Test Sample Presets */}
      <div className="mt-4 pt-1 flex flex-wrap items-center gap-2 text-xs">
        <span className="text-slate-400 font-medium flex items-center gap-1.5 mr-1">
          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
          Presets:
        </span>
        {PRESET_SAMPLES.map((sample, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => handleSelectPreset(sample.url)}
            disabled={isScanning}
            title={sample.desc}
            className={`px-3 py-1.5 rounded-xl border text-[11px] font-mono transition-all flex items-center gap-1.5 cursor-pointer ${
              sample.type === 'safe'
                ? 'bg-emerald-950/30 border-emerald-500/30 text-emerald-300 hover:bg-emerald-900/40 hover:border-emerald-400/50'
                : sample.type === 'phish'
                ? 'bg-rose-950/30 border-rose-500/30 text-rose-300 hover:bg-rose-900/40 hover:border-rose-400/50'
                : sample.type === 'suspicious'
                ? 'bg-amber-950/30 border-amber-500/30 text-amber-300 hover:bg-amber-900/40 hover:border-amber-400/50'
                : 'bg-indigo-950/30 border-indigo-500/30 text-indigo-300 hover:bg-indigo-900/40 hover:border-indigo-400/50'
            } disabled:opacity-50`}
          >
            {sample.type === 'safe' && <CheckCircle className="w-3 h-3 text-emerald-400" />}
            {sample.type === 'phish' && <ShieldAlert className="w-3 h-3 text-rose-400" />}
            {sample.type === 'suspicious' && <ShieldAlert className="w-3 h-3 text-amber-400" />}
            {sample.type === 'degraded' && <HelpCircle className="w-3 h-3 text-indigo-400" />}
            {sample.label}
          </button>
        ))}
      </div>

    </div>
  );
}
