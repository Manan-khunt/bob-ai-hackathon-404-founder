import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { GitMerge, ArrowRight, Activity, ShieldAlert, Cpu } from 'lucide-react';
import { useAppStore } from '../../store';
import AnimatedCounter from '../common/AnimatedCounter';

export default function SourceCorrelationGraph() {
  const navigate = useNavigate();
  const selectedIncidentId = useAppStore((s) => s.selectedIncidentId);
  const incidents = useAppStore((s) => s.incidents);
  const selectIncident = useAppStore((s) => s.selectIncident);

  const activeIncident =
    incidents.find((i) => i.id === selectedIncidentId) || incidents[0];

  const [activeSourceIndex, setActiveSourceIndex] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setActiveSourceIndex((prev) => (prev + 1) % 4);
    }, 2400);
    return () => clearInterval(timer);
  }, []);

  const sources = [
    { id: 'siem', name: 'SIEM Core', alert: 'Port Recon SYN Sequence', time: '10:42:15', type: 'SIEM' },
    { id: 'cyber', name: 'Cyber Sensor', alert: 'JA3 C2 Beacon Profile', time: '10:43:08', type: 'CYBER SENSOR' },
    { id: 'endpoint', name: 'Endpoint EDR', alert: 'lsass.exe Memory Injection', time: '10:44:12', type: 'ENDPOINT' },
    { id: 'intel', name: 'Strategic Intel', alert: 'APT-29 IP Attribution Match', time: '10:45:01', type: 'INTELLIGENCE' },
  ];

  return (
    <div className="bg-slate-900/95 border border-slate-800 rounded-lg p-5 shadow-defence flex flex-col justify-between select-none h-full">
      {/* Header */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <div className="flex items-center gap-2">
            <GitMerge className="w-4 h-4 text-sky-400" />
            <h3 className="text-xs font-bold text-white uppercase tracking-wider">
              DYNAMIC SOURCE CORRELATION
            </h3>
          </div>
          <div className="flex items-center gap-1.5 font-mono text-2xs">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-slate-300 font-semibold">4/4 CONSENSUS</span>
          </div>
        </div>
        <p className="text-xs text-slate-400 mb-3">
          Cross-sensor alignment verifying threat validity and eliminating single-point false positives.
        </p>

        {/* Dynamic Topology Container */}
        <div className="bg-slate-950/90 border border-slate-800/90 rounded-lg p-3.5 relative overflow-hidden">
          <div className="grid grid-cols-12 gap-3 items-center">
            {/* Left 5 cols: Source feeds */}
            <div className="col-span-5 space-y-2">
              {sources.map((src, idx) => {
                const isActive = activeSourceIndex === idx;
                return (
                  <motion.div
                    key={src.id}
                    whileHover={{ x: 2 }}
                    onClick={() => setActiveSourceIndex(idx)}
                    className={`p-2 rounded border text-left transition-all cursor-pointer ${
                      isActive
                        ? 'bg-slate-900 border-sky-500/70 shadow-md shadow-sky-950/60 ring-1 ring-sky-500/30'
                        : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] mb-0.5 font-mono">
                      <span className={`font-bold ${isActive ? 'text-sky-300' : 'text-slate-400'}`}>
                        {src.type}
                      </span>
                      <span className="text-slate-500 text-[9px]">{src.time}</span>
                    </div>
                    <div className="text-[11px] font-semibold text-slate-200 truncate leading-tight">
                      {src.name}
                    </div>
                    <div className="text-[9px] text-slate-400 truncate mt-0.5">
                      {src.alert}
                    </div>
                  </motion.div>
                );
              })}
            </div>

            {/* Middle 2 cols: Animated Stream Nexus */}
            <div className="col-span-2 flex flex-col items-center justify-center relative py-4">
              {/* Connector icon with animated ping */}
              <div className="w-8 h-8 rounded-full bg-sky-500/15 border border-sky-500/40 flex items-center justify-center text-sky-400 relative">
                <Activity className="w-4 h-4 animate-pulse" />
                <span className="absolute inset-0 rounded-full border border-sky-400/30 animate-ping" />
              </div>
              <div className="text-[9px] font-mono text-sky-300 uppercase tracking-widest mt-2 font-bold text-center leading-tight">
                FUSION MATRIX
              </div>
              <div className="w-px h-12 bg-gradient-to-b from-sky-500/50 via-slate-800 to-transparent my-1" />
              <div className="text-[8px] font-mono text-slate-500">
                Δt: 3m56s
              </div>
            </div>

            {/* Right 5 cols: Correlated Target Incident */}
            <div className="col-span-5">
              <motion.div
                whileHover={{ scale: 1.02 }}
                onClick={() => {
                  selectIncident(activeIncident.id);
                  navigate('/incidents');
                }}
                className="bg-slate-900 border-2 border-rose-500/70 rounded-lg p-3 shadow-xl shadow-rose-950/40 cursor-pointer text-left relative overflow-hidden group"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs font-bold text-rose-400 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
                    {activeIncident.id}
                  </span>
                  <span className="text-[9px] font-bold px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    {activeIncident.severity}
                  </span>
                </div>

                <div className="text-xs font-bold text-white leading-snug line-clamp-2">
                  {activeIncident.title}
                </div>

                <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-2xs">
                  <span className="text-slate-400 uppercase font-semibold text-[10px]">Confidence:</span>
                  <span className="font-mono font-bold text-emerald-400 text-xs">
                    <AnimatedCounter value={activeIncident.confidence} suffix="%" duration={800} />
                  </span>
                </div>

                <div className="flex items-center justify-between text-2xs mt-0.5">
                  <span className="text-slate-400 uppercase font-semibold text-[10px]">Score:</span>
                  <span className="font-mono font-extrabold text-rose-400 text-sm">
                    <AnimatedCounter value={activeIncident.priorityScore} suffix="/100" duration={850} />
                  </span>
                </div>

                <div className="mt-2 pt-1 border-t border-slate-800/60 text-[10px] text-sky-400 font-semibold group-hover:text-sky-300 flex items-center justify-between">
                  <span>Investigate</span>
                  <ArrowRight className="w-3 h-3 group-hover:translate-x-0.5 transition-transform" />
                </div>
              </motion.div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Metrics */}
      <div className="mt-3 pt-3 border-t border-slate-800 flex items-center justify-between text-2xs text-slate-400 font-mono">
        <span>Temporal Window: <strong className="text-slate-200">3m 56s</strong></span>
        <span>Threat Attribution: <strong className="text-sky-300">{activeIncident.attribution}</strong></span>
      </div>
    </div>
  );
}
