import React from 'react';
import { Shield, Lock, Terminal, Heart, Cpu, FileText } from 'lucide-react';

/**
 * Clean, structured Cybersecurity Footer with honest project disclaimers.
 */
export default function Footer({ onNavigate }) {
  return (
    <footer className="w-full border-t border-slate-800/80 bg-cyber-950/95 text-slate-400 text-xs py-10 mt-16 font-sans">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          
          {/* Brand & Project Info */}
          <div className="md:col-span-2 space-y-3">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <Shield className="w-4 h-4" />
              </div>
              <span className="font-display font-bold text-white text-base">PhishGuard AI</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-900 border border-slate-800 text-cyan-300">
                Stage 14 Release
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-md leading-relaxed">
              Real-Time AI/ML-Based Phishing Detection & Prevention System. Built as a comprehensive cybersecurity engineering project combining 43 lexical & live DOM heuristics, SSRF defense, and tuned XGBoost classification.
            </p>
            <div className="flex items-center gap-3 text-[11px] font-mono text-slate-500">
              <span className="flex items-center gap-1">
                <Lock className="w-3 h-3 text-cyan-400" />
                <span>Zero Private Logging</span>
              </span>
              <span>•</span>
              <span className="flex items-center gap-1">
                <Cpu className="w-3 h-3 text-indigo-400" />
                <span>FastAPI + XGBoost</span>
              </span>
            </div>
          </div>

          {/* Quick Navigation */}
          <div>
            <h4 className="text-xs font-mono font-semibold uppercase text-slate-200 tracking-wider mb-3">
              Application
            </h4>
            <ul className="space-y-2 text-xs">
              <li>
                <button
                  onClick={() => onNavigate && onNavigate('home')}
                  className="hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  Home & Overview
                </button>
              </li>
              <li>
                <button
                  onClick={() => onNavigate && onNavigate('scanner')}
                  className="hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  Interactive URL Scanner
                </button>
              </li>
              <li>
                <button
                  onClick={() => onNavigate && onNavigate('dashboard')}
                  className="hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  Security Telemetry Dashboard
                </button>
              </li>
              <li>
                <button
                  onClick={() => onNavigate && onNavigate('how-it-works')}
                  className="hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  Architecture & Pipeline
                </button>
              </li>
            </ul>
          </div>

          {/* Documentation & Limits */}
          <div>
            <h4 className="text-xs font-mono font-semibold uppercase text-slate-200 tracking-wider mb-3">
              Compliance & Ethics
            </h4>
            <ul className="space-y-2 text-xs">
              <li>
                <button
                  onClick={() => onNavigate && onNavigate('about')}
                  className="hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  Honest Model Limitations
                </button>
              </li>
              <li>
                <button
                  onClick={() => onNavigate && onNavigate('technology')}
                  className="hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  Technology Stack & Weights
                </button>
              </li>
              <li>
                <span className="text-slate-500">Student Cybersecurity Capstone</span>
              </li>
              <li>
                <span className="text-slate-500">Chromium MV3 Compliant</span>
              </li>
            </ul>
          </div>

        </div>

        {/* Bottom Bar with Academic Notice */}
        <div className="border-t border-slate-900 pt-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-[11px] text-slate-500">
          <div>
            © 2026 PhishGuard AI • Academic Cybersecurity Research & Prevention System.
          </div>
          <div className="font-mono text-slate-500 text-center sm:text-right">
            Never submit actual passwords or confidential tokens to external analyzers.
          </div>
        </div>

      </div>
    </footer>
  );
}
