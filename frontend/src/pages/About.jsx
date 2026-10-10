import React from 'react';
import { 
  Shield, 
  GraduationCap, 
  Layers, 
  Cpu, 
  AlertTriangle, 
  CheckCircle2, 
  Server, 
  Code2,
  Lock,
  ArrowLeft
} from 'lucide-react';

export default function About({ onBackToScanner }) {
  return (
    <div className="w-full max-w-4xl mx-auto px-4 py-8 animate-fadeIn">
      
      {/* Back Button */}
      <button
        onClick={onBackToScanner}
        className="mb-6 px-3.5 py-1.5 rounded-lg border border-slate-800 bg-cyber-900 text-xs text-slate-400 hover:text-cyan-300 hover:border-cyan-500/40 flex items-center gap-1.5 transition-colors font-medium"
      >
        <ArrowLeft className="w-3.5 h-3.5" />
        Back to Scanner
      </button>

      {/* Hero Header */}
      <div className="glass-card rounded-2xl p-8 border border-indigo-500/30 glow-indigo mb-8">
        <div className="flex items-center gap-3 mb-3">
          <div className="p-2.5 rounded-xl bg-indigo-500/15 border border-indigo-500/30 text-indigo-400">
            <GraduationCap className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl sm:text-3xl font-display font-bold text-white">
              About the PhishGuard Project
            </h1>
            <p className="text-xs font-mono text-indigo-300">
              Academic Machine Learning Cybersecurity System
            </p>
          </div>
        </div>

        <p className="text-sm text-slate-300 leading-relaxed mt-4">
          PhishGuard is an intelligent, multi-layered phishing website detection system developed as an academic research project. 
          It demonstrates how combining offline lexical URL heuristics with live HTML DOM content inspection significantly enhances classification precision compared to single-modality detectors.
        </p>
      </div>

      {/* System Architecture Section */}
      <div className="space-y-6 mb-10">
        <h2 className="text-lg font-display font-bold text-white flex items-center gap-2 border-b border-slate-800 pb-2">
          <Layers className="w-5 h-5 text-cyan-400" />
          Multi-Stage Detection Pipeline
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          
          <div className="glass-panel p-5 rounded-xl border border-slate-800">
            <div className="flex items-center gap-2 font-semibold text-sm text-cyan-300 mb-2">
              <span className="w-6 h-6 rounded-full bg-cyan-500/20 flex items-center justify-center text-xs font-mono text-cyan-400 border border-cyan-500/30">1</span>
              URL Lexical Feature Extraction
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Extracts 22 structural and linguistic features directly from the URL string, including IP address usage, excessive subdomain nesting, high character entropy, deceptive keywords, and brand impersonation patterns.
            </p>
          </div>

          <div className="glass-panel p-5 rounded-xl border border-slate-800">
            <div className="flex items-center gap-2 font-semibold text-sm text-indigo-300 mb-2">
              <span className="w-6 h-6 rounded-full bg-indigo-500/20 flex items-center justify-center text-xs font-mono text-indigo-400 border border-indigo-500/30">2</span>
              Guarded Live HTML DOM Inspection
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Fetches the webpage with strict timeouts (8s) and size limits (2MB). Parses the DOM to detect credential harvesting forms, external form action targets, hidden tracking iframes, and mismatched anchor hyperlinks.
            </p>
          </div>

          <div className="glass-panel p-5 rounded-xl border border-slate-800">
            <div className="flex items-center gap-2 font-semibold text-sm text-emerald-300 mb-2">
              <span className="w-6 h-6 rounded-full bg-emerald-500/20 flex items-center justify-center text-xs font-mono text-emerald-400 border border-emerald-500/30">3</span>
              Tuned Machine Learning Model
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Evaluates the 43-dimensional combined feature vector against an optimized XGBoost ensemble, utilizing tuned class weighting to balance detection sensitivity and false-alarm minimization.
            </p>
          </div>

          <div className="glass-panel p-5 rounded-xl border border-slate-800">
            <div className="flex items-center gap-2 font-semibold text-sm text-amber-300 mb-2">
              <span className="w-6 h-6 rounded-full bg-amber-500/20 flex items-center justify-center text-xs font-mono text-amber-400 border border-amber-500/30">4</span>
              Dual-Branch Degraded Mode
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              When live HTML is unreachable (timeout, DNS failure, or bot blocking), the engine executes a calibrated fallback: bounding clean URLs to medium/suspicious while still catching blatant URL-level threats.
            </p>
          </div>

        </div>
      </div>

      {/* Academic Disclaimers & Caveats */}
      <div className="glass-card rounded-2xl p-6 border border-amber-500/40 glow-warn mb-8">
        <div className="flex items-center gap-2.5 text-amber-300 font-semibold text-sm mb-3">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          Academic Scope & Security Caveats
        </div>
        <div className="text-xs sm:text-sm text-slate-300 space-y-2.5 leading-relaxed">
          <p>
            • <strong>Educational Prototype:</strong> This software is an academic demonstration created to evaluate heuristic feature engineering and machine learning techniques in web security.
          </p>
          <p>
            • <strong>Defense in Depth:</strong> PhishGuard should never be used as the sole line of defense against sophisticated cyber attacks. Always utilize multi-factor authentication (MFA) and reputable enterprise browser defenses.
          </p>
          <p>
            • <strong>Evolving Threat Landscapes:</strong> Attackers continuously alter techniques, utilizing zero-day domains, obfuscated scripts, and dynamic bot detection that may evade static ML models.
          </p>
        </div>
      </div>

      {/* Tech Stack Summary */}
      <div className="glass-panel rounded-2xl p-6 border border-slate-800 text-xs font-mono text-slate-400">
        <div className="text-slate-200 font-semibold text-xs uppercase tracking-wider mb-3">
          Technology Stack
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-2.5 rounded-lg bg-cyber-900 border border-slate-800">
            <span className="text-cyan-400 block font-bold">Frontend</span>
            React + Vite + Tailwind
          </div>
          <div className="p-2.5 rounded-lg bg-cyber-900 border border-slate-800">
            <span className="text-indigo-400 block font-bold">Backend</span>
            FastAPI + Uvicorn
          </div>
          <div className="p-2.5 rounded-lg bg-cyber-900 border border-slate-800">
            <span className="text-emerald-400 block font-bold">ML Model</span>
            XGBoost + Scikit-Learn
          </div>
          <div className="p-2.5 rounded-lg bg-cyber-900 border border-slate-800">
            <span className="text-amber-400 block font-bold">Parsing</span>
            BeautifulSoup4 + LXML
          </div>
        </div>
      </div>

    </div>
  );
}
