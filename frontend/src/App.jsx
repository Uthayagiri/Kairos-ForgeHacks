import React, { useState } from 'react';
import Header from './components/Header';
import Footer from './components/Footer';
import CursorSpotlight from './components/CursorSpotlight';
import ExtensionModal from './components/ExtensionModal';
import Home from './pages/Home';
import ScannerPage from './pages/ScannerPage';
import DashboardPage from './pages/DashboardPage';
import HowItWorksPage from './pages/HowItWorksPage';
import TechnologyPage from './pages/TechnologyPage';
import AboutPage from './pages/AboutPage';
import { useScan } from './hooks/useScan';

export default function App() {
  const [currentTab, setCurrentTab] = useState('home');
  const [isExtensionModalOpen, setIsExtensionModalOpen] = useState(false);
  const scanManager = useScan();

  const handleNavigateToScanner = (url) => {
    setCurrentTab('scanner');
    if (url) {
      scanManager.runScan(url);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-cyber-950 text-slate-100 cyber-grid relative selection:bg-cyan-500 selection:text-slate-950">
      
      {/* Interactive Cursor-Reactive Ambient Lighting */}
      <CursorSpotlight />

      {/* Background ambient lighting orbs */}
      <div className="fixed top-0 left-1/4 w-[500px] h-[500px] bg-cyan-500/8 rounded-full blur-[140px] pointer-events-none -z-10" />
      <div className="fixed bottom-0 right-1/4 w-[500px] h-[500px] bg-indigo-500/8 rounded-full blur-[140px] pointer-events-none -z-10" />

      {/* Main Top Header */}
      <Header
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        backendOnline={scanManager.backendOnline}
        backendLatency={scanManager.backendLatency}
        modelInfo={scanManager.modelInfo}
        onOpenExtensionModal={() => setIsExtensionModalOpen(true)}
      />

      {/* Main Content Router */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {currentTab === 'home' && (
          <Home
            scanManager={scanManager}
            onNavigate={(tab) => setCurrentTab(tab)}
            onOpenExtensionModal={() => setIsExtensionModalOpen(true)}
          />
        )}

        {currentTab === 'scanner' && (
          <ScannerPage scanManager={scanManager} />
        )}

        {currentTab === 'dashboard' && (
          <DashboardPage
            scanManager={scanManager}
            onNavigateToScanner={handleNavigateToScanner}
          />
        )}

        {currentTab === 'how-it-works' && (
          <HowItWorksPage
            onNavigateToScanner={handleNavigateToScanner}
          />
        )}

        {currentTab === 'technology' && (
          <TechnologyPage />
        )}

        {currentTab === 'about' && (
          <AboutPage
            onBackToScanner={() => setCurrentTab('scanner')}
          />
        )}
      </main>

      {/* Footer */}
      <Footer onNavigate={(tab) => setCurrentTab(tab)} />

      {/* Browser Extension Installation & Simulator Modal */}
      <ExtensionModal
        isOpen={isExtensionModalOpen}
        onClose={() => setIsExtensionModalOpen(false)}
        onLaunchScanner={handleNavigateToScanner}
      />

    </div>
  );
}
