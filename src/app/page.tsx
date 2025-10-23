'use client';

import { useState } from 'react';
import CombinedSecurityDashboard from "./TCPAnalysisDashboard";
import PacketReplay from "./PacketReplay";
import { Shield, Network } from 'lucide-react';

export default function Home() {
  const [currentView, setCurrentView] = useState<'dashboard' | 'packet-replay'>('dashboard');

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Navigation Bar */}
      <nav className="bg-slate-900 border-b border-slate-700 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-2">
              <Shield className="w-8 h-8 text-blue-400" />
              <h1 className="text-xl font-bold text-white">Network Security Suite</h1>
            </div>
            
            <div className="flex gap-2">
              <button
                onClick={() => setCurrentView('dashboard')}
                className={`px-6 py-2 rounded-lg transition-all transform hover:scale-105 flex items-center gap-2 ${
                  currentView === 'dashboard'
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/50'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                <Shield className="w-5 h-5" />
                Security Dashboard
              </button>
              
              <button
                onClick={() => setCurrentView('packet-replay')}
                className={`px-6 py-2 rounded-lg transition-all transform hover:scale-105 flex items-center gap-2 ${
                  currentView === 'packet-replay'
                    ? 'bg-green-600 text-white shadow-lg shadow-green-500/50'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                }`}
              >
                <Network className="w-5 h-5" />
                Packet Replay
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="transition-all duration-300">
        {currentView === 'dashboard' && <CombinedSecurityDashboard />}
        {currentView === 'packet-replay' && <PacketReplay />}
      </div>
    </div>
  );
}
