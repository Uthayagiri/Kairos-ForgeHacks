import React from 'react';
import { 
  ShieldAlert, 
  Info, 
  Lock, 
  AlertTriangle, 
  CheckCircle2, 
  Heart, 
  Layers, 
  Cpu, 
  ArrowLeft,
  FileText,
  HelpCircle
} from 'lucide-react';

export default function AboutPage({ onBackToScanner }) {
  const limitations = [
    {
      title: '1. Single URL Features Are Inconclusive',
      summary: 'No single lexical property proves malice or innocence.',
      detail:
        'A long domain, unusual subdomains, or special characters can exist on benign CDNs and analytics endpoints. PhishGuard AI evaluates the full 43-signal feature space together with live DOM inspection to avoid naive heuristic false positives.',
    },
    {
      title: '2. HTTPS Does NOT Guarantee Legitimacy',
      summary: 'Free automated TLS certificates are widely abused by attackers.',
      detail:
        'Modern phishing campaigns routinely obtain valid SSL/TLS certificates via automated certificate authorities (such as Let’s Encrypt or Cloudflare). The presence of the HTTPS padlock only means transport encryption is present—not that the domain owner is trustworthy.',
    },
    {
      title: '3. False Positives & False Negatives Occur',
      summary: 'Statistical ML models operate on probabilistic patterns.',
      detail:
        'Brand-new spear-phishing templates with zero lexical anomalies or legitimate sites with unconventional HTML structures may occasionally be misclassified. Detection scores represent risk indicators rather than absolute legal proof.',
    },
    {
      title: '4. JavaScript SPAs & Inaccessible Hosts (Degraded Mode)',
      summary: 'Websites requiring complex client-side JS hydration have bounded scores.',
      detail:
        'Single-page applications (React, Vue, Angular) often return blank HTML shells until JavaScript runs. Our engine detects SPA shells and unreachable hosts, falling back to offline URL heuristics with bounded confidence rather than assuming safety.',
    },
    {
      title: '5. Do NOT Submit Sensitive Passwords to Any Scanner',
      summary: 'Scanner inputs should only ever be public website URLs.',
      detail:
        'Users should never enter real passwords, session cookies, MFA tokens, or sensitive personal data into the URL bar or scanner input. PhishGuard AI never stores or requests authentication credentials.',
    },
  ];

  return (
    <div className="w-full max-w-5xl mx-auto py-8 px-4 sm:px-6 space-y-12 animate-fadeIn">
      
      {/* Header */}
      <div className="text-center max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-4">
          <Info className="w-3.5 h-3.5 text-cyan-400" />
          <span>Academic Project Context & Disclosure</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-display font-bold text-white tracking-tight">
          About & <span className="bg-gradient-to-r from-amber-400 to-rose-400 bg-clip-text text-transparent">Honest Limitations</span>
        </h1>
        <p className="text-xs sm:text-sm text-slate-300 mt-3.5 leading-relaxed max-w-2xl mx-auto">
          An honest, transparent appraisal of how AI-assisted phishing detection works, its realistic boundaries, and ethical cybersecurity guidelines.
        </p>
      </div>

      {/* Project Background Note */}
      <div className="glass-card rounded-3xl p-6 sm:p-8 border border-cyan-500/30 shadow-xl">
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shrink-0">
            <Heart className="w-6 h-6" />
          </div>
          <div className="space-y-3">
            <h3 className="text-lg font-display font-bold text-white">
              Student Cybersecurity Engineering Project
            </h3>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
              <strong>PhishGuard AI</strong> was built as an academic capstone and research demonstrator exploring the synergy between <em>lexical URL heuristic analysis</em>, <em>live DOM structure inspection</em>, and <em>gradient-boosted tree classification</em>.
            </p>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
              Unlike commercial black-box tools that claim unverifiable 99.9% detection rates, PhishGuard AI prioritizes <strong>interpretability</strong>, <strong>SSRF defense</strong>, <strong>degraded-mode transparency</strong>, and <strong>privacy-first Chromium extension architecture</strong>.
            </p>
          </div>
        </div>
      </div>

      {/* Honest Limitations Section */}
      <div className="space-y-6">
        <div className="text-center max-w-xl mx-auto">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-amber-950/40 border border-amber-500/30 text-amber-300 text-xs font-mono mb-2">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Cybersecurity Realities</span>
          </div>
          <h3 className="text-2xl font-display font-bold text-white">
            Five Critical Limitations
          </h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {limitations.map((item, idx) => (
            <div
              key={idx}
              className={`p-6 rounded-3xl glass-card border border-slate-800 hover:border-amber-500/30 transition-all ${
                idx === limitations.length - 1 ? 'md:col-span-2' : ''
              }`}
            >
              <h4 className="text-sm font-bold text-white mb-1 font-display">
                {item.title}
              </h4>
              <div className="text-xs font-semibold text-amber-300 mb-2 font-mono">
                {item.summary}
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                {item.detail}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Back to Scanner CTA */}
      {onBackToScanner && (
        <div className="text-center pt-4">
          <button
            onClick={onBackToScanner}
            className="px-6 py-3 rounded-2xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-mono text-xs font-bold transition-all inline-flex items-center gap-2 cursor-pointer shadow-lg shadow-cyan-500/20"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back to Interactive Scanner</span>
          </button>
        </div>
      )}

    </div>
  );
}
