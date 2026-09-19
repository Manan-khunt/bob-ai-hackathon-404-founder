import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Bell,
  Play,
  RotateCcw,
  Bot,
  UserCheck,
  ChevronDown,
  Clock,
  Sparkles,
  CheckCircle2,
} from 'lucide-react';
import { useAppStore } from '../../store';

const PAGE_TITLES = {
  '/': 'Threat Intelligence Overview',
  '/alerts': 'Multi-Source Alert Intelligence Feed',
  '/incidents': 'Incident Investigation & Asset Containment',
  '/mitre': 'Adversary Tactics & MITRE ATT&CK Matrix',
  '/bluf': 'Commander Bottom Line Up Front (BLUF) Briefings',
  '/sources': 'Multi-Source Telemetry & Sensor Health',
  '/bob': 'Bob AI Intelligence Analyst Workspace',
  '/settings': 'System Calibration & Fusion Policy Settings',
};

export default function TopCommandBar() {
  const location = useLocation();
  const title = PAGE_TITLES[location.pathname] || 'Defence Intelligence Command';

  const operationalStatus = useAppStore((s) => s.operationalStatus);
  const toggleBob = useAppStore((s) => s.toggleBob);
  const isBobOpen = useAppStore((s) => s.isBobOpen);
  const demoState = useAppStore((s) => s.demoState);
  const startCoordinatedIntrusionDemo = useAppStore((s) => s.startCoordinatedIntrusionDemo);
  const startBenignNoiseDemo = useAppStore((s) => s.startBenignNoiseDemo);
  const resetDemo = useAppStore((s) => s.resetDemo);

  const [secondsAgo, setSecondsAgo] = useState(4);
  const [showDemoMenu, setShowDemoMenu] = useState(false);
  const [currentTime, setCurrentTime] = useState('');

  useEffect(() => {
    const timer = setInterval(() => {
      setSecondsAgo((prev) => (prev >= 60 ? 1 : prev + 1));
      const now = new Date();
      setCurrentTime(
        now.toLocaleTimeString('en-US', {
          hour12: false,
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        }) + ' UTC'
      );
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <motion.header
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: 'easeOut' }}
      className="h-16 bg-slate-950/90 border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-20 backdrop-blur-md select-none"
    >
      {/* Page Title & Status */}
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
            {title}
          </h1>
          <div className="flex items-center gap-3 text-2xs text-slate-400 mt-0.5 font-mono">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              LIVE {currentTime || 'STREAM'}
            </span>
            <span>•</span>
            <span>
              Data Freshness:{' '}
              <strong className="text-slate-300 font-semibold">{secondsAgo}s ago</strong>
            </span>
          </div>
        </div>

        <div className="h-6 w-px bg-slate-800 hidden md:block" />

        <div className="hidden lg:flex items-center gap-2">
          <span className="text-2xs text-slate-400 uppercase font-semibold">Status:</span>
          <span
            className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-2xs font-semibold transition-colors ${
              operationalStatus === 'CRITICAL'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                operationalStatus === 'CRITICAL' ? 'bg-rose-400 animate-pulse' : 'bg-emerald-400'
              }`}
            />
            {operationalStatus}
          </span>
        </div>
      </div>

      {/* Right Controls: Demo Mode, Bob AI, Profile */}
      <div className="flex items-center gap-3">
        {/* Interactive Demo Mode Dropdown with Motion */}
        <div className="relative">
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => setShowDemoMenu(!showDemoMenu)}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-semibold border transition-all ${
              demoState.active
                ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 shadow-sm shadow-amber-500/20 animate-pulse'
                : 'bg-slate-900 text-slate-200 border-slate-700 hover:bg-slate-800'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>DEMO MODE</span>
            {demoState.active && (
              <span className="text-2xs px-1.5 py-0.2 rounded bg-amber-400 text-slate-950 font-bold">
                STEP {demoState.currentStep}/10
              </span>
            )}
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </motion.button>

          <AnimatePresence>
            {showDemoMenu && (
              <motion.div
                initial={{ opacity: 0, y: 6, scale: 0.96 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 4, scale: 0.96 }}
                transition={{ duration: 0.16, ease: 'easeOut' }}
                className="absolute right-0 mt-2 w-72 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl p-2 z-50 text-xs"
              >
                <div className="px-2 py-1 text-2xs font-semibold uppercase tracking-wider text-slate-400 border-b border-slate-800 mb-1">
                  Select Hackathon Scenario
                </div>

                <button
                  onClick={() => {
                    startCoordinatedIntrusionDemo();
                    setShowDemoMenu(false);
                  }}
                  className="w-full text-left px-2.5 py-2 rounded hover:bg-slate-800 text-slate-200 flex flex-col gap-0.5 transition-colors"
                >
                  <div className="flex items-center gap-2 font-semibold text-sky-300">
                    <Play className="w-3 h-3 text-sky-400" />
                    1. Coordinated Intrusion (Live 10-Step)
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Multi-source alert surge, correlation, and instant BLUF synthesis.
                  </div>
                </button>

                <button
                  onClick={() => {
                    startBenignNoiseDemo();
                    setShowDemoMenu(false);
                  }}
                  className="w-full text-left px-2.5 py-2 rounded hover:bg-slate-800 text-slate-200 flex flex-col gap-0.5 transition-colors"
                >
                  <div className="flex items-center gap-2 font-semibold text-emerald-300">
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                    2. Benign Noise (False Positive Triage)
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Demonstrates 91.4% automated noise suppression.
                  </div>
                </button>

                <div className="border-t border-slate-800 mt-1 pt-1">
                  <button
                    onClick={() => {
                      resetDemo();
                      setShowDemoMenu(false);
                    }}
                    className="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-rose-300 flex items-center gap-2 font-medium"
                  >
                    <RotateCcw className="w-3 h-3 text-rose-400" />
                    Reset to Baseline
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Bob AI Quick Trigger Button */}
        <motion.button
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          onClick={toggleBob}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-semibold border transition-all ${
            isBobOpen
              ? 'bg-sky-600/30 text-sky-200 border-sky-500 shadow-sm shadow-sky-900/50'
              : 'bg-slate-900 text-slate-300 border-slate-700 hover:bg-slate-800 hover:text-white'
          }`}
        >
          <Bot className="w-4 h-4 text-sky-400" />
          <span className="hidden sm:inline">Bob AI</span>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" title="Bob AI Online" />
        </motion.button>

        {/* Notifications Icon with animated badge */}
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          className="w-8 h-8 rounded-md bg-slate-900 border border-slate-700 flex items-center justify-center text-slate-300 hover:text-white hover:bg-slate-800 relative"
        >
          <Bell className="w-4 h-4" />
          <span className="absolute top-1 right-1 w-2 h-2 bg-rose-500 rounded-full animate-ping" />
          <span className="absolute top-1 right-1 w-2 h-2 bg-rose-500 rounded-full" />
        </motion.button>

        {/* User Officer Badge */}
        <div className="flex items-center gap-2 pl-2 border-l border-slate-800 text-xs">
          <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-slate-300 font-semibold text-2xs">
            <UserCheck className="w-4 h-4 text-sky-400" />
          </div>
          <div className="hidden xl:block text-left leading-tight">
            <div className="font-semibold text-white text-2xs">SENIOR ANALYST</div>
            <div className="text-[10px] text-slate-400">DEFENCE OPS</div>
          </div>
        </div>
      </div>
    </motion.header>
  );
}
