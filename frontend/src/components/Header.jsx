import React from 'react';
import { Shield, Activity, Layers, BarChart3, HelpCircle, Terminal, Info, ExternalLink, Compass } from 'lucide-react';

/**
 * Top Futuristic Navigation Header with live ML engine status telemetry pill
 * and direct navigation actions.
 */
export default function Header({
  currentTab,
  setCurrentTab,
  backendOnline,
  backendLatency,
  modelInfo,
  onOpenExtensionModal,
}) {
  const navItems = [
    { id: 'home', label: 'Home', icon: Shield },
    { id: 'scanner', label: 'Live Scanner', icon: Terminal },
    { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
    { id: 'how-it-works', label: 'How It Works', icon: Layers },
    { id: 'technology', label: 'Technology', icon: Activity },
    { id: 'about', label: 'About & Limits', icon: Info },
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-cyber-950/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Logo and Brand */}
        <div 
          onClick={() => setCurrentTab('home')}
          className="flex items-center gap-3 cursor-pointer select-none group"
        >
          <div className="relative p-2 rounded-xl bg-cyan-950/60 border border-cyan-500/40 text-cyan-400 group-hover:border-cyan-400 group-hover:shadow-lg group-hover:shadow-cyan-500/20 transition-all duration-300">
            <Shield className="w-5 h-5" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping opacity-75" />
          </div>

          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-display font-bold text-base sm:text-lg tracking-tight text-white group-hover:text-cyan-300 transition-colors">
                PhishGuard
              </span>
              <span className="font-display font-extrabold text-base sm:text-lg bg-gradient-to-r from-cyan-400 to-indigo-400 bg-clip-text text-transparent">
                AI
              </span>
              <span className="hidden sm:inline-block text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-900 border border-slate-800 text-slate-400">
                v1.2
              </span>
            </div>
            <div className="hidden sm:block text-[10px] font-mono text-slate-400 -mt-0.5">
              AI/ML Phishing Detection System
            </div>
          </div>
        </div>

        {/* Desktop Navigation Links */}
        <nav className="hidden lg:flex items-center gap-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setCurrentTab(item.id)}
                className={`px-3 py-1.5 rounded-xl text-xs font-mono font-medium transition-all flex items-center gap-1.5 cursor-pointer ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Action Controls & Backend Health Pill */}
        <div className="flex items-center gap-2.5 sm:gap-3">
          
          {/* Backend Status Telemetry Pill */}
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-mono border transition-all ${
              backendOnline === true
                ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                : backendOnline === false
                ? 'bg-rose-950/30 border-rose-500/40 text-rose-300'
                : 'bg-slate-900 border-slate-800 text-slate-400'
            }`}
            title={
              backendOnline === true
                ? `FastAPI Backend Active (${backendLatency ? `${backendLatency}ms` : 'online'})`
                : 'FastAPI Backend Offline (Start uvicorn on :8000)'
            }
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                backendOnline === true
                  ? 'bg-emerald-400 animate-pulse'
                  : backendOnline === false
                  ? 'bg-rose-500'
                  : 'bg-slate-500'
              }`}
            />
            <span className="hidden sm:inline">
              {backendOnline === true
                ? `ML Engine Active${backendLatency ? ` • ${backendLatency}ms` : ''}`
                : backendOnline === false
                ? 'Backend Offline'
                : 'Connecting...'}
            </span>
            <span className="sm:hidden">
              {backendOnline === true ? 'ML Live' : 'Offline'}
            </span>
          </div>

          {/* Extension Install CTA Modal Button */}
          <button
            onClick={onOpenExtensionModal}
            className="px-3 sm:px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-mono text-xs font-bold transition-all shadow-md shadow-cyan-500/20 flex items-center gap-1.5 cursor-pointer"
          >
            <Compass className="w-3.5 h-3.5 text-slate-950" />
            <span className="hidden sm:inline">Browser Extension</span>
            <span className="sm:hidden">Extension</span>
          </button>

        </div>

      </div>

      {/* Mobile Sub-Navigation Bar */}
      <div className="lg:hidden flex items-center gap-1 px-4 py-2 border-t border-slate-900 bg-slate-950/90 overflow-x-auto scrollbar-none">
        {navItems.map((item) => {
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setCurrentTab(item.id)}
              className={`px-3 py-1 rounded-lg text-[11px] font-mono whitespace-nowrap transition-all cursor-pointer ${
                isActive
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {item.label}
            </button>
          );
        })}
      </div>

    </header>
  );
}
