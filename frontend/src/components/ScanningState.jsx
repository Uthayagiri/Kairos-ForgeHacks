import React, { useState, useEffect } from 'react';
import { Shield, Cpu, Globe, Search, Layers } from 'lucide-react';

const SCAN_PHASES = [
  {
    icon: Globe,
    title: 'Validating URL Structure',
    description: 'Deconstructing hostname, checking HTTPS, parsing subdomain hierarchies and suspicious TLDs...',
  },
  {
    icon: Search,
    title: 'Live HTML & DOM Inspection',
    description: 'Retrieving live page with security bounds, parsing login forms, anchor ratios, and hidden iframes...',
  },
  {
    icon: Layers,
    title: 'Feature Vector Assembly',
    description: 'Computing 43 combined lexical, statistical, structural, and content-based heuristic indicators...',
  },
  {
    icon: Cpu,
    title: 'XGBoost Model Inference',
    description: 'Evaluating decision trees and computing calibrated phishing probability score...',
  },
];

export default function ScanningState({ targetUrl }) {
  const [activePhaseIndex, setActivePhaseIndex] = useState(0);

  useEffect(() => {
    // Advance scanning phase smoothly over ~3 seconds
    const interval = setInterval(() => {
      setActivePhaseIndex((prev) => (prev < SCAN_PHASES.length - 1 ? prev + 1 : prev));
    }, 700);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="w-full max-w-3xl mx-auto my-8">
      <div className="glass-card rounded-2xl p-8 border border-cyan-500/30 glow-cyan relative overflow-hidden">
        
        {/* Subtle scanning bar background pulse */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-transparent via-cyan-400 to-indigo-500 animate-pulse" />

        <div className="flex flex-col items-center text-center">
          
          {/* Radar Animation Circle */}
          <div className="relative w-24 h-24 mb-6 flex items-center justify-center">
            {/* Outer pulsating rings */}
            <div className="absolute inset-0 rounded-full border border-cyan-500/20 animate-ping opacity-25" />
            <div className="absolute inset-2 rounded-full border border-cyan-500/40 animate-pulse" />
            <div className="absolute inset-4 rounded-full border border-indigo-500/30" />
            
            {/* Rotating radar line */}
            <div className="absolute inset-0 rounded-full animate-radar-sweep border-t-2 border-r-2 border-cyan-400/80 pointer-events-none" />
            
            {/* Center icon */}
            <div className="relative p-3 rounded-full bg-cyber-900 border border-cyan-400/50 text-cyan-400 shadow-lg shadow-cyan-500/30">
              <Shield className="w-7 h-7 animate-pulse" />
            </div>
          </div>

          <h3 className="text-xl font-display font-bold text-white mb-1">
            Analyzing Target Webpage
          </h3>
          
          <p className="text-xs font-mono text-cyan-300/80 max-w-xl truncate px-4 py-1.5 rounded-lg bg-cyber-950/70 border border-cyan-500/20 mb-6">
            {targetUrl}
          </p>

          {/* Stepped Progress Stages */}
          <div className="w-full grid grid-cols-1 sm:grid-cols-2 gap-3 text-left">
            {SCAN_PHASES.map((phase, idx) => {
              const Icon = phase.icon;
              const isDone = idx < activePhaseIndex;
              const isCurrent = idx === activePhaseIndex;

              return (
                <div
                  key={idx}
                  className={`p-3.5 rounded-xl border transition-all duration-300 flex items-start gap-3 ${
                    isCurrent
                      ? 'bg-cyan-950/40 border-cyan-400/60 shadow-md shadow-cyan-500/10 scale-[1.02]'
                      : isDone
                      ? 'bg-slate-900/60 border-slate-700/60 opacity-90'
                      : 'bg-cyber-950/40 border-slate-800/40 opacity-40'
                  }`}
                >
                  <div
                    className={`p-2 rounded-lg mt-0.5 ${
                      isCurrent
                        ? 'bg-cyan-500/20 text-cyan-300 animate-pulse'
                        : isDone
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : 'bg-slate-800 text-slate-500'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                  </div>

                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-semibold text-slate-200">
                        {phase.title}
                      </span>
                      {isCurrent && (
                        <span className="flex h-1.5 w-1.5 relative">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                          <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-cyan-500" />
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-slate-400 leading-tight mt-0.5">
                      {phase.description}
                    </p>
                  </div>
                </div>
              );
            })}
          </div>

          <p className="text-[11px] text-slate-500 mt-6 italic">
            * Live network inspections may take 2-4 seconds to safely inspect external server headers, certificates, and DOM structure.
          </p>

        </div>
      </div>
    </div>
  );
}
