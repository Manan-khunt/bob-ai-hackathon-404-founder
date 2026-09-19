import React from 'react';
import Sidebar from './Sidebar';
import TopCommandBar from './TopCommandBar';
import WorkflowBreadcrumb from './WorkflowBreadcrumb';
import AlertDetailDrawer from '../alerts/AlertDetailDrawer';
import FalsePositiveEvidenceModal from '../alerts/FalsePositiveEvidenceModal';
import BobAssistantPanel from '../bob/BobAssistantPanel';
import { useAppStore } from '../../store';
import { Sparkles, Play, RotateCcw } from 'lucide-react';

export default function AppLayout({ children }) {
  const demoState = useAppStore((s) => s.demoState);
  const resetDemo = useAppStore((s) => s.resetDemo);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-950 text-slate-100 antialiased font-sans">
      {/* Left Navigation Sidebar */}
      <Sidebar />

      {/* Center & Main Content Column */}
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        {/* Top Operational Command Bar */}
        <TopCommandBar />

        {/* Primary Operational Workflow Breadcrumb */}
        <WorkflowBreadcrumb />

        {/* Live Demo Mode Banner (when active) */}
        {demoState.active && (
          <div className="bg-gradient-to-r from-amber-500/20 via-sky-500/20 to-purple-500/20 border-b border-amber-500/40 px-6 py-2 flex items-center justify-between text-xs animate-fade-in select-none">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
              <strong className="text-amber-300 font-bold uppercase tracking-wider">
                ACTIVE DEMO SCENARIO: {demoState.scenarioName}
              </strong>
              <span className="text-slate-400 mx-1">•</span>
              <span className="text-slate-200 font-medium">
                {demoState.statusText}
              </span>
            </div>

            <button
              onClick={resetDemo}
              className="text-2xs font-bold uppercase px-2.5 py-1 rounded bg-slate-900/80 hover:bg-slate-900 text-rose-300 border border-rose-500/30 flex items-center gap-1 transition-colors"
            >
              <RotateCcw className="w-3 h-3 text-rose-400" />
              Exit Demo
            </button>
          </div>
        )}

        {/* Main View Area */}
        <main className="flex-1 overflow-y-auto p-4 lg:p-6 bg-slate-950">
          {children}
        </main>
      </div>

      {/* Global Modals & Drawers */}
      <AlertDetailDrawer />
      <FalsePositiveEvidenceModal />
      <BobAssistantPanel />
    </div>
  );
}
