import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, HelpCircle } from 'lucide-react';

export default function RiskBadge({ status = 'safe', riskLevel = 'low', size = 'md' }) {
  const normalizedStatus = (status || '').toLowerCase();
  const normalizedRisk = (riskLevel || '').toLowerCase();

  let config = {
    bg: 'bg-emerald-950/40',
    border: 'border-emerald-500/40',
    text: 'text-emerald-300',
    icon: ShieldCheck,
    label: 'Legitimate / Safe',
    riskText: 'Low Risk',
    glow: 'glow-safe',
  };

  if (normalizedStatus === 'phishing' || normalizedRisk === 'high') {
    config = {
      bg: 'bg-rose-950/40',
      border: 'border-rose-500/50',
      text: 'text-rose-300',
      icon: ShieldAlert,
      label: 'Phishing Threat Detected',
      riskText: 'High Risk',
      glow: 'glow-danger',
    };
  } else if (normalizedStatus === 'suspicious' || normalizedRisk === 'medium') {
    config = {
      bg: 'bg-amber-950/40',
      border: 'border-amber-500/50',
      text: 'text-amber-300',
      icon: AlertTriangle,
      label: 'Suspicious / Caution',
      riskText: 'Medium Risk',
      glow: 'glow-warn',
    };
  } else if (normalizedStatus === 'error' || normalizedRisk === 'unknown') {
    config = {
      bg: 'bg-slate-900/60',
      border: 'border-slate-700/60',
      text: 'text-slate-400',
      icon: HelpCircle,
      label: 'Analysis Error',
      riskText: 'Unknown Risk',
      glow: '',
    };
  }

  const Icon = config.icon;

  if (size === 'sm') {
    return (
      <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-[11px] font-medium border ${config.bg} ${config.border} ${config.text}`}>
        <Icon className="w-3 h-3" />
        <span className="capitalize">{normalizedStatus}</span>
        <span className="opacity-60 font-mono">({config.riskText})</span>
      </span>
    );
  }

  if (size === 'lg') {
    return (
      <div className={`inline-flex items-center gap-2.5 px-4 py-2 rounded-xl text-sm font-semibold border ${config.bg} ${config.border} ${config.text} ${config.glow}`}>
        <Icon className="w-5 h-5" />
        <span>{config.label}</span>
        <span className="px-2 py-0.5 rounded-md bg-black/30 border border-white/10 text-xs font-mono">
          {config.riskText}
        </span>
      </div>
    );
  }

  // Default size: md
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium border ${config.bg} ${config.border} ${config.text}`}>
      <Icon className="w-3.5 h-3.5" />
      <span>{config.label}</span>
      <span className="opacity-70 font-mono">({config.riskText})</span>
    </span>
  );
}
