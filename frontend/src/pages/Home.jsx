import React from 'react';
import { 
  Shield, 
  Search, 
  Cpu, 
  Layers, 
  Lock, 
  Terminal,
  ArrowRight,
  Sparkles,
  Activity,
  CheckCircle2,
  FileCode,
  Compass
} from 'lucide-react';
import CyberShield from '../components/CyberShield';
import OutcomeCards from '../components/OutcomeCards';
import ScanInput from '../components/ScanInput';
import ScanningState from '../components/ScanningState';
import ResultCard from '../components/ResultCard';
import ErrorState from '../components/ErrorState';
import ParticleNetwork from '../components/ParticleNetwork';

export default function Home({ scanManager, onNavigate, onOpenExtensionModal }) {
  const {
    isScanning,
    currentResult,
    error,
    scannedUrl,
    runScan,
    clearCurrent,
  } = scanManager;

  const scrollToScanner = () => {
    const el = document.getElementById('scanner-section');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="w-full space-y-16">
      
      {/* Hero Section */}
      <section className="relative pt-6 pb-12 px-4 sm:px-6 flex flex-col items-center justify-center text-center overflow-hidden">
        
        {/* Canvas Particle Constellation in background */}
        <ParticleNetwork />

        {/* Ambient top light */}
        <div className="absolute -top-16 left-1/2 -translate-x-1/2 w-[600px] h-[350px] bg-gradient-to-b from-cyan-500/15 via-indigo-500/10 to-transparent blur-3xl pointer-events-none -z-10" />

        {/* Top Product Announcement Pill */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-950/60 border border-cyan-500/30 text-cyan-300 text-xs font-mono mb-6 shadow-lg shadow-cyan-500/10 backdrop-blur-md">
          <Shield className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span>Stage 14 Active • 43 Heuristic Signals + SSRF Defense</span>
        </div>

        {/* Hero Main Headline */}
        <h1 className="text-3xl sm:text-5xl lg:text-6xl font-display font-extrabold tracking-tight text-white max-w-4xl mx-auto leading-[1.15]">
          Your First Line of Defense <br className="hidden sm:inline" />
          <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400 bg-clip-text text-transparent">
            Against Phishing Threats
          </span>
        </h1>

        {/* Supporting Subtext */}
        <p className="mt-5 text-sm sm:text-base lg:text-lg text-slate-300 max-w-2xl mx-auto leading-relaxed font-sans">
          Analyze suspicious URLs, understand website risk, and make safer browsing decisions with real-time AI-assisted phishing detection and browser protection.
        </p>

        {/* Call to Actions */}
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3.5">
          <button
            onClick={scrollToScanner}
            className="px-6 py-3.5 rounded-2xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-mono text-xs sm:text-sm font-bold transition-all shadow-xl shadow-cyan-500/20 hover:shadow-cyan-500/30 hover:scale-[1.02] flex items-center gap-2 cursor-pointer border border-cyan-300/40"
          >
            <Search className="w-4 h-4 text-slate-950" />
            <span>Analyze a URL</span>
            <ArrowRight className="w-4 h-4 text-slate-950 opacity-80" />
          </button>

          <button
            onClick={onOpenExtensionModal}
            className="px-6 py-3.5 rounded-2xl bg-slate-900/90 hover:bg-slate-800 border border-slate-700/80 hover:border-cyan-500/40 text-slate-200 font-mono text-xs sm:text-sm font-semibold transition-all flex items-center gap-2 cursor-pointer shadow-lg backdrop-blur-md"
          >
            <Compass className="w-4 h-4 text-cyan-400" />
            <span>Explore Extension</span>
          </button>
        </div>

        {/* Interactive Cybersecurity Shield & Radar Visualizer */}
        <div className="mt-12 w-full max-w-2xl">
          <CyberShield status="neutral" interactive={true} />
        </div>

      </section>

      {/* Outcome Cards Section */}
      <section className="px-4 sm:px-6">
        <OutcomeCards onSelectPreset={(sampleUrl) => {
          runScan(sampleUrl);
          scrollToScanner();
        }} />
      </section>

      {/* Main Interactive URL Scanner Section */}
      <section id="scanner-section" className="px-4 sm:px-6 pt-4 pb-8 scroll-mt-20">
        <div className="text-center max-w-2xl mx-auto mb-8">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900 border border-slate-800 text-cyan-300 text-xs font-mono mb-2">
            <Terminal className="w-3.5 h-3.5" />
            <span>Interactive URL Threat Workbench</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-display font-bold text-white tracking-tight">
            Inspect Any Website in Real Time
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 mt-2">
            Enter a destination to extract lexical features, inspect HTML forms, and execute ML classification.
          </p>
        </div>

        {/* Scanner Input */}
        <ScanInput
          onScan={runScan}
          isScanning={isScanning}
          initialUrl={scannedUrl}
        />

        {/* Dynamic State Views */}
        <div className="mt-8">
          {isScanning && (
            <ScanningState targetUrl={scannedUrl} />
          )}

          {error && !isScanning && (
            <ErrorState
              error={error}
              onRetry={() => runScan(scannedUrl)}
              onClear={clearCurrent}
            />
          )}

          {currentResult && !isScanning && !error && (
            <ResultCard
              result={currentResult}
              onClear={clearCurrent}
              onReScan={() => runScan(scannedUrl)}
            />
          )}
        </div>

      </section>

      {/* Architecture Highlights Quick Grid */}
      <section className="px-4 sm:px-6 py-6 border-t border-slate-900">
        <div className="max-w-5xl mx-auto grid grid-cols-1 sm:grid-cols-3 gap-5">
          
          <div className="glass-card p-6 rounded-2xl border border-slate-800/80 hover:border-cyan-500/40 transition-all duration-300">
            <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 w-fit mb-3">
              <Layers className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-semibold text-white mb-1.5 font-display">
              Multi-Stage Feature Extraction
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Extracts 43 distinct lexical signals, entropy scores, domain structure, and live DOM forms with SSRF defense.
            </p>
          </div>

          <div className="glass-card p-6 rounded-2xl border border-slate-800/80 hover:border-indigo-500/40 transition-all duration-300">
            <div className="p-3 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 w-fit mb-3">
              <Cpu className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-semibold text-white mb-1.5 font-display">
              Tuned XGBoost ML Ensemble
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Trained and calibrated on stratified datasets with bounded confidence thresholds for degraded network modes.
            </p>
          </div>

          <div className="glass-card p-6 rounded-2xl border border-slate-800/80 hover:border-emerald-500/40 transition-all duration-300">
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 w-fit mb-3">
              <Compass className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-semibold text-white mb-1.5 font-display">
              Real-Time Browser Protection
            </h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Chrome and Edge extension with active tab monitoring, zero credential logging, and safe warning overlays.
            </p>
          </div>

        </div>
      </section>

    </div>
  );
}
