import React from 'react';
import { 
  Cpu, 
  Layers, 
  Code2, 
  FileCode, 
  Terminal, 
  Shield, 
  Compass, 
  Database, 
  Activity, 
  Server, 
  Lock, 
  Sparkles 
} from 'lucide-react';

export default function TechnologyPage() {
  const techStack = [
    {
      category: 'Machine Learning & Heuristics',
      items: [
        {
          name: 'XGBoost 2.1.0',
          role: 'Primary Gradient-Boosted Classification Tree Ensemble',
          details: 'Tuned with early stopping on stratified test splits; handles non-linear feature interactions.',
        },
        {
          name: 'Scikit-learn',
          role: 'Baseline Modeling, Preprocessing & Evaluation',
          details: 'Used for baseline comparisons (RandomForest, Logistic Regression) and metric scoring.',
        },
        {
          name: '43 Heuristic Feature Extractors',
          role: 'Domain-Engineered Feature Vector Pipeline',
          details: '18 deterministic lexical & statistical URL signals + 25 live HTML DOM heuristics.',
        },
      ],
    },
    {
      category: 'Backend & High-Speed API',
      items: [
        {
          name: 'Python 3.13',
          role: 'Core Backend Language & Runtime Environment',
          details: 'Modern async Python runtime with type hints and defensive validation bounds.',
        },
        {
          name: 'FastAPI & Uvicorn',
          role: 'High-Performance Asynchronous REST API',
          details: 'Provides OpenAPI /docs telemetry, CORS middleware, and sub-10ms route handling.',
        },
        {
          name: 'BeautifulSoup4 & lxml',
          role: 'DOM Parsing & Security Form Extraction',
          details: 'Parses password fields, external form action ratios, tracking iframes, and null anchors.',
        },
        {
          name: 'SSRF Perimeter Guard',
          role: 'DNS Resolution & Internal IP Filtering',
          details: 'Blocks private RFC 1918 networks, loopback hosts, and cloud metadata (169.254.169.254).',
        },
      ],
    },
    {
      category: 'Frontend & Interactive Web App',
      items: [
        {
          name: 'React 18 & Vite 6',
          role: 'Modern Single Page Application Framework',
          details: 'Ultra-fast HMR builds, component-driven modularity, and client-side telemetry state management.',
        },
        {
          name: 'TailwindCSS & Vanilla CSS',
          role: 'Futuristic Dark Cyber Design System',
          details: 'Atmospheric neon glows, glassmorphism, responsive cursor lighting, and smooth risk meters.',
        },
        {
          name: 'Lucide React Icons',
          role: 'Cybersecurity Iconography',
          details: 'Consistent, clean vector iconography for threat signals, statuses, and metrics.',
        },
      ],
    },
    {
      category: 'Browser Extension & Client Security',
      items: [
        {
          name: 'Manifest V3 (Chromium)',
          role: 'Chrome & Microsoft Edge Extension Architecture',
          details: 'Service worker background scripts with minimal permissions (activeTab, storage).',
        },
        {
          name: 'Safe Warning Interstitial (warning.html)',
          role: 'Pre-Navigation Threat Interception',
          details: 'Safe screen for high-risk phishing destinations with deliberate override mechanisms.',
        },
        {
          name: 'Zero Private Data Telemetry',
          role: 'Strict Privacy Protocol',
          details: 'No passwords, session tokens, form values, or private browsing history transmitted.',
        },
      ],
    },
  ];

  return (
    <div className="w-full max-w-6xl mx-auto py-8 px-4 sm:px-6 space-y-12 animate-fadeIn">
      
      {/* Header */}
      <div className="text-center max-w-3xl mx-auto">
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-4">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span>Integrated Technology Stack</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-display font-bold text-white tracking-tight">
          Modern, Transparent <span className="bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">Cybersecurity Stack</span>
        </h1>
        <p className="text-xs sm:text-sm text-slate-300 mt-3.5 leading-relaxed max-w-2xl mx-auto">
          An honest overview of every framework, machine learning library, backend service, and security layer actively integrated into PhishGuard AI.
        </p>
      </div>

      {/* Tech Stack Categories Grid */}
      <div className="space-y-8">
        {techStack.map((category, catIdx) => (
          <div key={catIdx} className="glass-card rounded-3xl p-6 sm:p-8 border border-slate-800 shadow-xl">
            <h3 className="text-lg font-display font-bold text-white mb-4 pb-3 border-b border-slate-800 flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              <span>{category.category}</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {category.items.map((item, itemIdx) => (
                <div key={itemIdx} className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/30 transition-all">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-bold text-white font-mono">{item.name}</span>
                  </div>
                  <div className="text-xs font-semibold text-cyan-300 mb-1.5 font-sans">
                    {item.role}
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    {item.details}
                  </p>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

    </div>
  );
}
