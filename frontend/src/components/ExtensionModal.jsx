import React, { useState } from 'react';
import { 
  X, 
  Download, 
  CheckCircle2, 
  ExternalLink, 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  ShieldX, 
  Cpu, 
  Settings, 
  RotateCw, 
  Layers, 
  Lock,
  Compass,
  ArrowRight
} from 'lucide-react';

/**
 * Extension Installation Guide & Interactive Live Browser Extension Simulator.
 */
export default function ExtensionModal({ isOpen, onClose, onLaunchScanner }) {
  const [activeTab, setActiveTab] = useState('install'); // 'install' or 'simulator'
  const [simUrl, setSimUrl] = useState('https://en.wikipedia.org/wiki/Phishing');
  const [simRisk, setSimRisk] = useState(1.2);
  const [simStatus, setSimStatus] = useState('safe');
  const [simActiveGroup, setSimActiveGroup] = useState('url'); // 'url', 'domain', 'html'

  if (!isOpen) return null;

  const handleSimulate = (url, status, risk) => {
    setSimUrl(url);
    setSimStatus(status);
    setSimRisk(risk);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-fadeIn">
      
      {/* Modal Container */}
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto glass-card border border-cyan-500/30 rounded-3xl p-6 sm:p-8 shadow-2xl shadow-cyan-950/50 flex flex-col">
        
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-5 right-5 p-2 rounded-xl bg-slate-900 border border-slate-700 text-slate-400 hover:text-white hover:border-cyan-500/50 transition-all cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Compass className="w-7 h-7" />
          </div>
          <div>
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 text-[11px] font-mono mb-1">
              <span>Manifest V3 • Chromium & Edge</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-display font-bold text-white">
              PhishGuard AI Browser Extension
            </h2>
          </div>
        </div>

        {/* Navigation Tabs inside modal */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3 mb-6">
          <button
            onClick={() => setActiveTab('install')}
            className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition-all cursor-pointer ${
              activeTab === 'install'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Installation Guide (3 Steps)
          </button>
          <button
            onClick={() => setActiveTab('simulator')}
            className={`px-4 py-2 rounded-xl text-xs font-mono font-semibold transition-all cursor-pointer ${
              activeTab === 'simulator'
                ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 shadow-sm shadow-indigo-500/10'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Live Extension Popup Simulator
          </button>
        </div>

        {/* Tab 1: Installation Guide */}
        {activeTab === 'install' && (
          <div className="space-y-6">
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              PhishGuard AI includes a complete Chromium extension built with <strong className="text-cyan-300">Manifest V3</strong>. It monitors the active tab in real time, requests minimum permissions (<code className="text-indigo-300 font-mono">activeTab</code>, <code className="text-indigo-300 font-mono">storage</code>), and never logs private passwords or tokens.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              
              {/* Step 1 */}
              <div className="p-5 rounded-2xl glass-panel border border-slate-800 flex flex-col justify-between">
                <div>
                  <div className="w-8 h-8 rounded-full bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 font-mono text-xs font-bold flex items-center justify-center mb-3">
                    01
                  </div>
                  <h4 className="text-sm font-semibold text-white mb-2">Open Extensions Manager</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Navigate to <code className="text-cyan-300 font-mono">chrome://extensions</code> in Chrome or <code className="text-cyan-300 font-mono">edge://extensions</code> in Microsoft Edge.
                  </p>
                </div>
                <div className="mt-4 text-[11px] font-mono text-slate-500">
                  Toggle "Developer mode" in the top-right corner.
                </div>
              </div>

              {/* Step 2 */}
              <div className="p-5 rounded-2xl glass-panel border border-slate-800 flex flex-col justify-between">
                <div>
                  <div className="w-8 h-8 rounded-full bg-indigo-500/20 border border-indigo-500/40 text-indigo-300 font-mono text-xs font-bold flex items-center justify-center mb-3">
                    02
                  </div>
                  <h4 className="text-sm font-semibold text-white mb-2">Load Unpacked</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Click the <strong className="text-white">"Load unpacked"</strong> button and select the <code className="text-cyan-300 font-mono">extension/</code> directory from this project workspace.
                  </p>
                </div>
                <div className="mt-4 text-[11px] font-mono text-slate-500">
                  Target: /S5_Phishing_Detector/extension
                </div>
              </div>

              {/* Step 3 */}
              <div className="p-5 rounded-2xl glass-panel border border-slate-800 flex flex-col justify-between">
                <div>
                  <div className="w-8 h-8 rounded-full bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 font-mono text-xs font-bold flex items-center justify-center mb-3">
                    03
                  </div>
                  <h4 className="text-sm font-semibold text-white mb-2">Pin & Scan Active Tabs</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Pin the <strong className="text-white">PhishGuard AI</strong> icon to your toolbar. Click it on any website for instant active-tab threat classification.
                  </p>
                </div>
                <div className="mt-4 text-[11px] font-mono text-slate-500">
                  Connects seamlessly to local API :8000
                </div>
              </div>

            </div>

            {/* Architecture and Privacy Assurance */}
            <div className="p-4 rounded-2xl bg-cyan-950/30 border border-cyan-500/20 flex items-start gap-3">
              <Lock className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
              <div className="text-xs text-slate-300 leading-relaxed">
                <strong className="text-white">Privacy by Architecture:</strong> The extension only accesses the active tab URL upon explicit popup activation or navigation safety checks. It ignores <code className="font-mono text-cyan-300">chrome://</code> and internal browser schemes.
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
              <button
                onClick={() => setActiveTab('simulator')}
                className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold transition-all flex items-center gap-2 cursor-pointer shadow-lg shadow-cyan-500/20"
              >
                <span>Try Interactive Extension Simulator</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>

              <button
                onClick={onClose}
                className="px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300 transition-all cursor-pointer"
              >
                Close Window
              </button>
            </div>
          </div>
        )}

        {/* Tab 2: Live Extension Popup Simulator */}
        {activeTab === 'simulator' && (
          <div className="space-y-6">
            <div className="text-xs text-slate-300">
              Below is an exact replica of the <strong className="text-cyan-300">PhishGuard AI Chrome/Edge Popup</strong>. Test how it evaluates different live web scenarios:
            </div>

            {/* Preset scenario buttons */}
            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => handleSimulate('https://en.wikipedia.org/wiki/Phishing', 'safe', 1.2)}
                className={`px-3 py-1.5 rounded-xl text-xs font-mono transition-all cursor-pointer ${
                  simStatus === 'safe'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                Scenario A: Legitimate Portal (Wikipedia)
              </button>
              <button
                onClick={() => handleSimulate('http://paypa1-security-verification.top/auth', 'suspicious', 64.0)}
                className={`px-3 py-1.5 rounded-xl text-xs font-mono transition-all cursor-pointer ${
                  simStatus === 'suspicious'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                Scenario B: Suspicious Homoglyph (PayPal Typo)
              </button>
              <button
                onClick={() => handleSimulate('http://192.168.1.100/secure-banking/login.php', 'phishing', 92.5)}
                className={`px-3 py-1.5 rounded-xl text-xs font-mono transition-all cursor-pointer ${
                  simStatus === 'phishing'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                    : 'bg-slate-900 border border-slate-800 text-slate-400 hover:text-white'
                }`}
              >
                Scenario C: Phishing Harvest (Raw IP Trap)
              </button>
            </div>

            {/* Simulated Extension Popup Box */}
            <div className="max-w-md mx-auto rounded-3xl bg-[#080c14] border border-slate-700/80 p-5 shadow-2xl shadow-black/80 font-sans text-slate-100 relative overflow-hidden">
              
              {/* Extension Header */}
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3 mb-4">
                <div className="flex items-center gap-2.5">
                  <div className="p-1.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                    <Shield className="w-4 h-4" />
                  </div>
                  <div>
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-bold text-white tracking-tight">PhishGuard</span>
                      <span className="text-xs font-bold text-cyan-400">AI</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">v0.1.0</span>
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono">Chromium Protection Engine</div>
                  </div>
                </div>

                <div className="flex items-center gap-1">
                  <button className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800">
                    <RotateCw className="w-3.5 h-3.5" />
                  </button>
                  <button className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800">
                    <Settings className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Target Tab Address Bar */}
              <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center gap-2 mb-4">
                <Compass className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                <span className="text-xs font-mono text-slate-300 truncate">{simUrl}</span>
              </div>

              {/* Circular Risk Indicator & Status Banner */}
              <div className={`p-4 rounded-2xl border mb-4 flex items-center gap-4 ${
                simStatus === 'safe'
                  ? 'bg-emerald-950/20 border-emerald-500/30'
                  : simStatus === 'suspicious'
                  ? 'bg-amber-950/20 border-amber-500/30'
                  : 'bg-rose-950/20 border-rose-500/30'
              }`}>
                
                {/* Gauge Circle */}
                <div className="relative w-14 h-14 flex items-center justify-center shrink-0">
                  <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                    <path
                      className="text-slate-800"
                      strokeWidth="3.5"
                      stroke="currentColor"
                      fill="none"
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                    <path
                      className={
                        simStatus === 'safe'
                          ? 'text-emerald-400'
                          : simStatus === 'suspicious'
                          ? 'text-amber-400'
                          : 'text-rose-500'
                      }
                      strokeDasharray={`${simRisk}, 100`}
                      strokeWidth="3.5"
                      strokeLinecap="round"
                      stroke="currentColor"
                      fill="none"
                      d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    />
                  </svg>
                  <div className="absolute text-[11px] font-mono font-bold text-white">
                    {simRisk}%
                  </div>
                </div>

                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                    Active Tab Verdict
                  </div>
                  <div className="text-sm font-bold text-white capitalize">
                    {simStatus === 'safe' ? 'Legitimate Domain' : simStatus === 'suspicious' ? 'Suspicious Activity' : 'Phishing Threat'}
                  </div>
                  <div className="text-[11px] text-slate-400 font-sans mt-0.5">
                    {simStatus === 'safe'
                      ? 'Safe for authentication & browsing'
                      : simStatus === 'suspicious'
                      ? 'Exercise caution: verify address bar'
                      : 'Critical hazard: block or avoid data input'}
                  </div>
                </div>

              </div>

              {/* 3 Signal Groups Filter Tabs */}
              <div className="grid grid-cols-3 gap-1 p-1 rounded-xl bg-slate-950 border border-slate-800 mb-3 text-center">
                <button
                  onClick={() => setSimActiveGroup('url')}
                  className={`py-1 text-[10px] font-mono rounded-lg transition-all ${
                    simActiveGroup === 'url' ? 'bg-slate-800 text-cyan-300 font-bold' : 'text-slate-400'
                  }`}
                >
                  URL Signals
                </button>
                <button
                  onClick={() => setSimActiveGroup('domain')}
                  className={`py-1 text-[10px] font-mono rounded-lg transition-all ${
                    simActiveGroup === 'domain' ? 'bg-slate-800 text-cyan-300 font-bold' : 'text-slate-400'
                  }`}
                >
                  Domain & IP
                </button>
                <button
                  onClick={() => setSimActiveGroup('html')}
                  className={`py-1 text-[10px] font-mono rounded-lg transition-all ${
                    simActiveGroup === 'html' ? 'bg-slate-800 text-cyan-300 font-bold' : 'text-slate-400'
                  }`}
                >
                  DOM & Forms
                </button>
              </div>

              {/* Signal Details Content */}
              <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800/80 text-[11px] text-slate-300 space-y-1.5 mb-4">
                {simActiveGroup === 'url' && (
                  <>
                    <div className="flex justify-between">
                      <span className="text-slate-400">HTTPS Encryption:</span>
                      <span className="font-mono text-cyan-300">{simStatus === 'safe' ? 'Yes (TLS 1.3)' : 'No (Insecure HTTP)'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Suspicious Keywords:</span>
                      <span className="font-mono">{simStatus === 'safe' ? 'None' : 'Detected (auth, login)'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Lexical Entropy:</span>
                      <span className="font-mono">{simStatus === 'safe' ? '3.12 (Low)' : '4.85 (High)'}</span>
                    </div>
                  </>
                )}

                {simActiveGroup === 'domain' && (
                  <>
                    <div className="flex justify-between">
                      <span className="text-slate-400">TLD Classification:</span>
                      <span className="font-mono">{simStatus === 'safe' ? '.org (Standard)' : '.top (High Risk)'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">IP Host Obfuscation:</span>
                      <span className="font-mono">{simStatus === 'phishing' ? 'Yes (Raw IPv4)' : 'No (Standard DNS)'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">SSRF Guard Status:</span>
                      <span className="font-mono text-emerald-400">Protected</span>
                    </div>
                  </>
                )}

                {simActiveGroup === 'html' && (
                  <>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Password Input Fields:</span>
                      <span className="font-mono">{simStatus === 'phishing' ? '1 (External Action)' : '0'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Null Anchor Ratio:</span>
                      <span className="font-mono">{simStatus === 'safe' ? '0.0%' : '35.4%'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">DOM Analysis Mode:</span>
                      <span className="font-mono text-indigo-300">Live HTML Inspected</span>
                    </div>
                  </>
                )}
              </div>

              {/* Bottom Actions in Simulator */}
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => {
                    onClose();
                    if (onLaunchScanner) onLaunchScanner(simUrl);
                  }}
                  className="py-2 px-3 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-[11px] font-mono text-cyan-300 font-semibold transition-all text-center cursor-pointer"
                >
                  Open in Web Scanner
                </button>
                <button
                  onClick={() => alert(`Simulated scanning active tab: ${simUrl}`)}
                  className="py-2 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-slate-200 transition-all text-center cursor-pointer"
                >
                  Rescan Active Tab
                </button>
              </div>

            </div>

          </div>
        )}

      </div>

    </div>
  );
}
