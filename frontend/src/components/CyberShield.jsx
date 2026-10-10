import React, { useState } from 'react';
import { Shield, ShieldAlert, ShieldCheck, ShieldX, Sparkles, Activity, Lock, Cpu } from 'lucide-react';

/**
 * Futuristic Glowing Cyber Shield visualization with multi-layer radar rings,
 * dynamic threat color shifts, and telemetry metrics.
 */
export default function CyberShield({ status = 'neutral', interactive = true }) {
  const [activeMode, setActiveMode] = useState(status || 'neutral');

  const modeConfig = {
    neutral: {
      color: 'from-cyan-500 to-indigo-500',
      glow: 'shadow-cyan-500/20 text-cyan-400 border-cyan-500/30',
      bgGlow: 'bg-cyan-500/10',
      icon: Shield,
      label: 'AI THREAT RADAR ACTIVE',
      badge: 'ML Engine Online',
      desc: 'Continuous real-time lexical & DOM inspection',
    },
    safe: {
      color: 'from-emerald-400 to-teal-500',
      glow: 'shadow-emerald-500/30 text-emerald-400 border-emerald-500/40',
      bgGlow: 'bg-emerald-500/15',
      icon: ShieldCheck,
      label: 'THREAT VERDICT: LEGITIMATE',
      badge: 'Risk Score: 1.2% (Low)',
      desc: 'TLS Verified • Authentic Anchor Network • Clean Heuristics',
    },
    suspicious: {
      color: 'from-amber-400 to-orange-500',
      glow: 'shadow-amber-500/30 text-amber-400 border-amber-500/40',
      bgGlow: 'bg-amber-500/15',
      icon: ShieldAlert,
      label: 'THREAT VERDICT: SUSPICIOUS',
      badge: 'Risk Score: 64.0% (Medium)',
      desc: 'Deceptive Subdomain • Uncommon TLD • Bounded Heuristic',
    },
    phishing: {
      color: 'from-rose-500 to-red-600',
      glow: 'shadow-rose-500/35 text-rose-400 border-rose-500/45',
      bgGlow: 'bg-rose-500/20',
      icon: ShieldX,
      label: 'THREAT VERDICT: PHISHING',
      badge: 'Risk Score: 92.5% (Critical)',
      desc: 'Credential Harvest Trap • Raw IP Host • Malicious Form Action',
    },
  };

  const current = modeConfig[activeMode] || modeConfig.neutral;
  const CurrentIcon = current.icon;

  return (
    <div className="relative flex flex-col items-center justify-center p-6 select-none">
      
      {/* Background Radial Glow */}
      <div className={`absolute w-72 h-72 rounded-full blur-3xl transition-all duration-700 pointer-events-none -z-10 ${current.bgGlow}`} />

      {/* Main Shield Animation Container */}
      <div className="relative w-48 h-48 flex items-center justify-center">
        
        {/* Outer Radar Rings */}
        <div className="absolute inset-0 rounded-full border border-cyan-500/20 animate-ping opacity-25" style={{ animationDuration: '3s' }} />
        <div className="absolute -inset-4 rounded-full border border-indigo-500/15 animate-pulse-glow" />
        <div className="absolute -inset-8 rounded-full border border-slate-700/30 border-dashed animate-radar-sweep" style={{ animationDuration: '18s' }} />

        {/* Inner Glowing Hexagon / Shield Core */}
        <div className={`relative z-10 w-28 h-28 rounded-3xl glass-card flex flex-col items-center justify-center border ${current.glow} transition-all duration-500 shadow-2xl backdrop-blur-2xl group`}>
          
          <div className="relative">
            <CurrentIcon className="w-12 h-12 transition-transform duration-300 group-hover:scale-110" />
            <div className="absolute -inset-1 blur-md opacity-40 bg-current -z-10" />
          </div>

          <div className="mt-2 flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider text-slate-400">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            <span>XGB-2.1</span>
          </div>

        </div>

        {/* Orbiting Satellite Security Nodes */}
        <div className="absolute top-0 right-4 px-2 py-0.5 rounded-full glass-panel border border-cyan-500/30 text-[10px] font-mono text-cyan-300 flex items-center gap-1 shadow-lg shadow-cyan-950/50">
          <Lock className="w-2.5 h-2.5" />
          <span>SSRF Guard</span>
        </div>

        <div className="absolute bottom-2 left-2 px-2 py-0.5 rounded-full glass-panel border border-indigo-500/30 text-[10px] font-mono text-indigo-300 flex items-center gap-1 shadow-lg shadow-indigo-950/50">
          <Cpu className="w-2.5 h-2.5" />
          <span>43 Heuristics</span>
        </div>

      </div>

      {/* Telemetry Status Pill */}
      <div className="mt-6 text-center">
        <div className={`inline-flex items-center gap-2 px-3.5 py-1 rounded-full text-xs font-mono border transition-all duration-500 ${current.glow} ${current.bgGlow}`}>
          <Activity className="w-3.5 h-3.5 animate-pulse" />
          <span className="font-semibold">{current.label}</span>
        </div>
        <p className="text-xs text-slate-400 mt-2 max-w-xs font-sans leading-relaxed">
          {current.desc}
        </p>
      </div>

      {/* Interactive State Demo Switcher */}
      {interactive && (
        <div className="mt-4 flex items-center gap-1.5 p-1 rounded-xl glass-panel border border-slate-800">
          <button
            onClick={() => setActiveMode('neutral')}
            className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-all ${
              activeMode === 'neutral' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Radar
          </button>
          <button
            onClick={() => setActiveMode('safe')}
            className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-all ${
              activeMode === 'safe' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Safe
          </button>
          <button
            onClick={() => setActiveMode('suspicious')}
            className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-all ${
              activeMode === 'suspicious' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Suspicious
          </button>
          <button
            onClick={() => setActiveMode('phishing')}
            className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-all ${
              activeMode === 'phishing' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Phishing
          </button>
        </div>
      )}

    </div>
  );
}
