import React from 'react';
import { 
  AlertCircle, 
  CheckCircle2, 
  Lock, 
  Unlock, 
  Server, 
  FileCode, 
  ExternalLink, 
  Info,
  ShieldAlert,
  AlertTriangle
} from 'lucide-react';

function getIndicatorIconAndSeverity(text) {
  const lower = (text || '').toLowerCase();

  // 1. High-Confidence Threat Signals (Crimson / Red)
  if (
    lower.includes('raw ip address') ||
    lower.includes("'@' symbol") ||
    lower.includes('high-risk or commonly abused') ||
    lower.includes('open redirection') ||
    lower.includes('external third-party domain') ||
    lower.includes('hidden or zero-dimension iframe') ||
    lower.includes('certificate verification failed') ||
    lower.includes('high-risk verdict is driven') ||
    lower.includes('unsupported url scheme')
  ) {
    return {
      icon: ShieldAlert,
      color: 'text-rose-400 bg-rose-950/40 border-rose-500/30',
      badge: 'High Threat',
      badgeColor: 'text-rose-300 bg-rose-900/40 border-rose-600/40',
    };
  }

  // 2. Risk Factors & Warning Heuristics (Amber / Warning)
  if (
    lower.includes('does not use secure https') ||
    lower.includes('does not use https') ||
    lower.includes('unencrypted') ||
    lower.includes('sensitive or authentication-related keywords') ||
    lower.includes('url shortening service') ||
    lower.includes('excessive number of subdomains') ||
    lower.includes('non-standard port') ||
    lower.includes('percent-encoded characters') ||
    lower.includes('form submission action is empty') ||
    lower.includes('suspicious javascript') ||
    lower.includes('meta refresh') ||
    lower.includes('misleading anchor text') ||
    lower.includes('high proportion of external hyperlinks') ||
    lower.includes('authentication or login form') ||
    lower.includes('password input field') ||
    lower.includes('could not be inspected') ||
    lower.includes('threat level is bounded')
  ) {
    return {
      icon: AlertTriangle,
      color: 'text-amber-400 bg-amber-950/40 border-amber-500/30',
      badge: 'Warning',
      badgeColor: 'text-amber-300 bg-amber-900/40 border-amber-600/40',
    };
  }

  // 3. Verified Positive / Safe Signals (Emerald / Green)
  if (
    lower.includes('encrypted https connection') ||
    lower.includes('standard domain and url structure') ||
    lower.includes('no credential harvesting forms') ||
    (lower.includes('https') && !lower.includes('not use')) ||
    lower.includes('clean domain') ||
    lower.includes('legitimate')
  ) {
    return {
      icon: CheckCircle2,
      color: 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30',
      badge: 'Positive',
      badgeColor: 'text-emerald-300 bg-emerald-900/40 border-emerald-600/40',
    };
  }

  // 4. General Informational Item (Cyan / Blue)
  return {
    icon: Info,
    color: 'text-cyan-400 bg-cyan-950/40 border-cyan-500/30',
    badge: 'Info',
    badgeColor: 'text-cyan-300 bg-cyan-900/40 border-cyan-600/40',
  };
}

export default function IndicatorsList({ indicators = [] }) {
  if (!indicators || indicators.length === 0) {
    return (
      <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 text-center text-xs text-slate-400">
        No specific threat indicators were flagged for this target.
      </div>
    );
  }

  return (
    <div className="space-y-2.5">
      {indicators.map((indicator, idx) => {
        const { icon: Icon, color, badge, badgeColor } = getIndicatorIconAndSeverity(indicator);

        return (
          <div
            key={idx}
            className={`p-3 rounded-xl border flex items-start justify-between gap-3 text-xs sm:text-sm ${color} transition-all duration-200 hover:scale-[1.005]`}
          >
            <div className="flex items-start gap-2.5 flex-1">
              <Icon className="w-4 h-4 mt-0.5 flex-shrink-0" />
              <span className="text-slate-200 leading-relaxed">
                {indicator}
              </span>
            </div>

            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium border flex-shrink-0 ${badgeColor}`}>
              {badge}
            </span>
          </div>
        );
      })}
    </div>
  );
}
