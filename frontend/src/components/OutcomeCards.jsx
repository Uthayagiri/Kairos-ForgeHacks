import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldX, CheckCircle, AlertTriangle, XCircle, ArrowRight } from 'lucide-react';

/**
 * Three clear product outcomes: SAFE, SUSPICIOUS, PHISHING
 * with rich interactive cards and realistic cybersecurity signals.
 */
export default function OutcomeCards({ onSelectPreset }) {
  const outcomes = [
    {
      type: 'safe',
      badge: 'SAFE VERDICT',
      title: 'Browse With Confidence',
      score: '< 25% Risk',
      border: 'hover:border-emerald-500/50 border-slate-800/80',
      bgGlow: 'hover:shadow-emerald-500/10',
      iconBg: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
      icon: ShieldCheck,
      desc: 'The website displays verified TLS domain certificates, clean structural entropy, authentic internal anchor ratios, and zero deceptive keywords.',
      signals: [
        'Legitimate domain authority match',
        'Balanced anchor link distribution',
        'Standard non-deceptive form actions',
      ],
      sampleUrl: 'https://en.wikipedia.org/wiki/Phishing',
      actionText: 'Test Safe Sample',
    },
    {
      type: 'suspicious',
      badge: 'SUSPICIOUS VERDICT',
      title: 'Pause & Verify Domain',
      score: '25% – 70% Risk',
      border: 'hover:border-amber-500/50 border-slate-800/80',
      bgGlow: 'hover:shadow-amber-500/10',
      iconBg: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
      icon: ShieldAlert,
      desc: 'Anomalies detected: deceptive brand subdomains, uncommon top-level domain, high lexical entropy, or unreachable live DOM content requiring caution.',
      signals: [
        'Brand typosquatting or homoglyphs',
        'Unusual sub-domain hierarchy depth',
        'Degraded mode with bounded confidence',
      ],
      sampleUrl: 'http://paypa1-security-verification-alert.top/signin/auth.html',
      actionText: 'Test Suspicious Sample',
    },
    {
      type: 'phishing',
      badge: 'PHISHING VERDICT',
      title: 'Block Or Avoid Threat',
      score: '> 70% Risk',
      border: 'hover:border-rose-500/50 border-slate-800/80',
      bgGlow: 'hover:shadow-rose-500/10',
      iconBg: 'bg-rose-500/10 border-rose-500/20 text-rose-400',
      icon: ShieldX,
      desc: 'Critical threat identified: raw IP host address, credential harvesting password fields posting to external unverified endpoints, or hidden tracking iframes.',
      signals: [
        'Credential harvesting trap detected',
        'Raw IP obfuscated host address',
        'Form action pointing to foreign host',
      ],
      sampleUrl: 'http://192.168.1.100/secure-banking/login.php',
      actionText: 'Test Phishing Sample',
    },
  ];

  return (
    <div className="w-full my-12">
      <div className="text-center max-w-2xl mx-auto mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400 text-xs font-mono mb-2">
          <span>Three Clear Operational Outcomes</span>
        </div>
        <h2 className="text-2xl sm:text-3xl font-display font-bold text-white tracking-tight">
          How PhishGuard AI <span className="bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">Protects You</span>
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 mt-2">
          From verified legitimate destinations to severe credential-harvesting threats.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {outcomes.map((item) => {
          const Icon = item.icon;
          return (
            <div
              key={item.type}
              className={`glass-card p-6 rounded-2xl border transition-all duration-300 flex flex-col justify-between shadow-xl ${item.border} ${item.bgGlow}`}
            >
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className={`p-3 rounded-xl border ${item.iconBg}`}>
                    <Icon className="w-6 h-6" />
                  </div>
                  <span className="text-[11px] font-mono font-semibold px-2.5 py-1 rounded-full bg-slate-900/90 border border-slate-700/60 text-slate-300">
                    {item.score}
                  </span>
                </div>

                <div className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 mb-1">
                  {item.badge}
                </div>
                <h3 className="text-lg font-display font-bold text-white mb-2">
                  {item.title}
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed mb-4">
                  {item.desc}
                </p>

                <div className="space-y-1.5 mb-5 border-t border-slate-800/80 pt-3.5">
                  {item.signals.map((sig, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-xs text-slate-400 font-sans">
                      <span className="text-cyan-400 mt-0.5">•</span>
                      <span>{sig}</span>
                    </div>
                  ))}
                </div>
              </div>

              {onSelectPreset && (
                <button
                  onClick={() => onSelectPreset(item.sampleUrl)}
                  className="w-full py-2.5 px-3 rounded-xl bg-slate-900/90 hover:bg-slate-800 border border-slate-700/60 hover:border-cyan-500/40 text-xs font-mono text-slate-200 hover:text-cyan-300 transition-all flex items-center justify-center gap-2 group cursor-pointer"
                >
                  <span>{item.actionText}</span>
                  <ArrowRight className="w-3.5 h-3.5 transition-transform group-hover:translate-x-1" />
                </button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
