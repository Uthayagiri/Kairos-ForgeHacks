import React, { useState } from 'react';
import { 
  Layers, 
  Search, 
  Globe, 
  Cpu, 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  Lock, 
  Database, 
  FileCode, 
  Compass, 
  ArrowRight,
  Sparkles,
  CheckCircle2
} from 'lucide-react';

export default function HowItWorksPage({ onNavigateToScanner }) {
  const [activeStep, setActiveStep] = useState(0);

  const pipelineSteps = [
    {
      step: 1,
      title: 'URL Input & Canonicalization',
      icon: Globe,
      color: 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10',
      summary: 'Normalization, defensive scheme validation, and length bounds checking.',
      detail:
        'The input string is sanitized, stripped of control characters, normalized to http/https protocols, and verified against unsupported schemes (such as javascript:, data:, or blob:).',
    },
    {
      step: 2,
      title: 'URL Feature Extraction',
      icon: Layers,
      color: 'text-indigo-400 border-indigo-500/30 bg-indigo-500/10',
      summary: 'Deterministic lexical signals: length, subdomains, entropy, and keywords.',
      detail:
        'Computes lexical entropy, checks for raw IPv4/IPv6 host addresses, evaluates suspicious TLD classifications, counts subdomains, and detects deceptive security tokens.',
    },
    {
      step: 3,
      title: 'Domain & SSRF Safety Checks',
      icon: Lock,
      color: 'text-sky-400 border-sky-500/30 bg-sky-500/10',
      summary: 'Perimeter DNS resolution and private network IP filtering.',
      detail:
        'Before making any live request, the backend resolves domain DNS records to verify the target does not point to internal RFC-1918 subnets, loopback hosts, or cloud instance metadata (169.254.169.254).',
    },
    {
      step: 4,
      title: 'Available Webpage Analysis',
      icon: FileCode,
      color: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
      summary: 'Guarded live HTML fetching, form action parsing, and iframe detection.',
      detail:
        'Streams HTML content up to a 2MB cap with an 8-second timeout. Analyzes password fields, external form destinations, null anchor ratios, and detects unhydrated SPA shells.',
    },
    {
      step: 5,
      title: 'ML Classification (XGBoost)',
      icon: Cpu,
      color: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
      summary: 'Gradient boosted decision trees over a 43-heuristic feature vector.',
      detail:
        'The assembled feature vector is fed to a tuned XGBoost ensemble calibrated for class imbalance to output a baseline phishing probability score.',
    },
    {
      step: 6,
      title: 'Risk Scoring & Prevention Action',
      icon: ShieldCheck,
      color: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
      summary: 'Bounded confidence mapping and Allow / Warn / Block recommendations.',
      detail:
        'Applies heuristic adjustments for degraded offline modes, assigns categorical risk (Low, Medium, High), and advises the user or extension whether to Allow, Warn, or Block navigation.',
    },
  ];

  const modules = [
    {
      id: 1,
      name: 'Data Collection & Preparation',
      icon: Database,
      tag: 'Stage 1–3 Pipeline',
      description:
        'Curates balanced legitimate URLs (Tranco Top 1M, Wikipedia, public government registries) and verified malicious phishing threats (PhishTank, OpenPhish) with automated deduplication and feature extraction.',
      points: [
        'Stratified sampling across 50,000+ benchmark samples',
        'Balanced class representation to prevent false-positive drift',
        'Automated offline dataset caching and validation splits',
      ],
    },
    {
      id: 2,
      name: 'Multi-Stage Feature Extraction',
      icon: Layers,
      tag: '43 Heuristic Signals',
      description:
        'Extracts a comprehensive hybrid feature vector combining 18 deterministic URL lexical characteristics with 25 live HTML DOM heuristics.',
      points: [
        'Shannon entropy of domain and URL path strings',
        'Punycode and homoglyph spoofing identification',
        'External password form action ratio and hidden iframe flags',
      ],
    },
    {
      id: 3,
      name: 'Machine Learning Classification',
      icon: Cpu,
      tag: 'XGBoost & Random Forest',
      description:
        'Tuned tree ensembles evaluate complex non-linear combinations of lexical and DOM signals with calibrated thresholding for incomplete or blocked responses.',
      points: [
        'Hyperparameter-tuned XGBoost 2.1.0 engine',
        'Bounded confidence safeguards for JavaScript SPA shells',
        'Sub-150ms average inference latency on CPU',
      ],
    },
    {
      id: 4,
      name: 'Browser Interface & Prevention',
      icon: Compass,
      tag: 'Chromium MV3 Extension',
      description:
        'Lightweight Manifest V3 extension providing active tab monitoring, instant circular risk meters, expandable forensic signals, and safe warning interstitial pages.',
      points: [
        'Zero credential logging or browsing history leaks',
        'Direct connection to local FastAPI detection engine',
        'Safe warning override mechanism with "Return to Safety"',
      ],
    },
  ];

  return (
    <div className="w-full max-w-6xl mx-auto py-8 px-4 sm:px-6 space-y-16 animate-fadeIn">
      
      {/* Top Section Header */}
      <div className="text-center max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-4">
          <Layers className="w-3.5 h-3.5 text-cyan-400" />
          <span>System Architecture & Pipeline</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-display font-bold text-white tracking-tight">
          How PhishGuard AI <span className="bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">Protects Users</span>
        </h1>
        <p className="text-xs sm:text-sm text-slate-300 mt-3.5 leading-relaxed max-w-2xl mx-auto">
          From incoming web request to machine learning inference and browser prevention: explore the end-to-end detection lifecycle.
        </p>
      </div>

      {/* 6-Stage Interactive Architecture Flow */}
      <div className="glass-card rounded-3xl p-6 sm:p-8 border border-slate-800 shadow-2xl">
        <div className="text-center max-w-xl mx-auto mb-8">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
            End-to-End Threat Pipeline
          </span>
          <h3 className="text-xl font-display font-bold text-white mt-1">
            The 6-Step Detection Flow
          </h3>
        </div>

        {/* Steps Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-8">
          {pipelineSteps.map((step, idx) => {
            const Icon = step.icon;
            const isSelected = activeStep === idx;
            return (
              <button
                key={step.step}
                onClick={() => setActiveStep(idx)}
                className={`p-4 rounded-2xl border text-left transition-all duration-300 flex flex-col justify-between cursor-pointer ${
                  isSelected
                    ? 'glass-card border-cyan-400/80 shadow-lg shadow-cyan-500/20 scale-[1.03] bg-cyan-950/40'
                    : 'glass-panel border-slate-800 hover:border-slate-700 opacity-80 hover:opacity-100'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-[11px] font-mono font-bold text-slate-400">0{step.step}</span>
                    <div className={`p-2 rounded-xl border ${step.color}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                  </div>
                  <h4 className="text-xs font-semibold text-white mb-1 leading-tight font-display">
                    {step.title}
                  </h4>
                </div>
                <div className="mt-3 text-[10px] font-mono text-cyan-300 flex items-center gap-1">
                  <span>Explore</span>
                  <ArrowRight className="w-3 h-3" />
                </div>
              </button>
            );
          })}
        </div>

        {/* Interactive Step Detail Callout Box */}
        <div className="p-6 rounded-2xl bg-cyber-950/80 border border-cyan-500/30 flex flex-col sm:flex-row items-start gap-4 animate-fadeIn">
          <div className="p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shrink-0">
            {React.createElement(pipelineSteps[activeStep].icon, { className: 'w-6 h-6' })}
          </div>
          <div>
            <div className="text-[11px] font-mono uppercase text-cyan-300 font-bold tracking-wider mb-1">
              Stage 0{pipelineSteps[activeStep].step} • {pipelineSteps[activeStep].title}
            </div>
            <h4 className="text-base font-bold text-white mb-1.5 font-display">
              {pipelineSteps[activeStep].summary}
            </h4>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
              {pipelineSteps[activeStep].detail}
            </p>
          </div>
        </div>

      </div>

      {/* 4 Deep-Dive Modules Section */}
      <div className="space-y-6">
        <div className="text-center max-w-xl mx-auto">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
            Core Engineering Pillars
          </span>
          <h3 className="text-2xl font-display font-bold text-white mt-1">
            The Four Core Modules
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {modules.map((mod) => {
            const Icon = mod.icon;
            return (
              <div
                key={mod.id}
                className="glass-card p-6 sm:p-7 rounded-3xl border border-slate-800 hover:border-cyan-500/40 transition-all duration-300 flex flex-col justify-between shadow-xl"
              >
                <div>
                  <div className="flex items-center justify-between mb-4">
                    <div className="p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                      <Icon className="w-6 h-6" />
                    </div>
                    <span className="text-[11px] font-mono px-2.5 py-1 rounded-full bg-slate-900 border border-slate-700 text-slate-300">
                      {mod.tag}
                    </span>
                  </div>

                  <h3 className="text-lg font-display font-bold text-white mb-2">
                    {mod.name}
                  </h3>
                  <p className="text-xs sm:text-sm text-slate-300 leading-relaxed mb-5">
                    {mod.description}
                  </p>

                  <div className="space-y-2 border-t border-slate-800/80 pt-4">
                    {mod.points.map((pt, i) => (
                      <div key={i} className="flex items-start gap-2 text-xs text-slate-400">
                        <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                        <span>{pt}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
}
