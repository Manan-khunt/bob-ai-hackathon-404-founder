import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  ShieldAlert,
  Server,
  Layers,
  Clock,
  CheckCircle2,
  Lock,
  Unlock,
  Radio,
  FileText,
  Activity,
  ArrowRight,
  ExternalLink,
  History,
  Network,
} from 'lucide-react';
import { useAppStore } from '../../store';
import AnimatedCounter from '../common/AnimatedCounter';

const TABS = [
  { id: 'evidence', label: 'Cross-Source Evidence', icon: Layers },
  { id: 'timeline', label: 'Event Timeline', icon: Clock },
  { id: 'assets', label: 'Affected Assets & Containment', icon: Server },
  { id: 'blast_radius', label: 'Blast Radius & Risk', icon: Network },
  { id: 'historical', label: 'Similar Historical Incidents', icon: History },
];

export default function IncidentInvestigationWorkspace() {
  const selectedIncidentId = useAppStore((s) => s.selectedIncidentId);
  const incidents = useAppStore((s) => s.incidents);
  const selectIncident = useAppStore((s) => s.selectIncident);
  const isolateAsset = useAppStore((s) => s.isolateAsset);

  const incident =
    incidents.find((i) => i.id === selectedIncidentId) || incidents[0];
  const bluf = incident.bluf;

  const [activeTab, setActiveTab] = useState('evidence');

  return (
    <div className="space-y-5 select-none">
      {/* Incident Switcher Ribbon */}
      <div className="flex items-center gap-2 overflow-x-auto scrollbar-none pb-1">
        <span className="text-2xs uppercase tracking-wider text-slate-400 font-semibold shrink-0">
          Correlated Queue:
        </span>
        {incidents.map((inc) => (
          <button
            key={inc.id}
            onClick={() => selectIncident(inc.id)}
            className={`px-3 py-1.5 rounded text-xs font-mono font-semibold transition-all shrink-0 flex items-center gap-2 border ${
              inc.id === incident.id
                ? 'bg-sky-500/20 text-sky-200 border-sky-500/40 shadow-sm'
                : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <span>{inc.id}</span>
            <span
              className={`text-2xs px-1 py-0.2 rounded ${
                inc.severity === 'CRITICAL'
                  ? 'bg-rose-500/30 text-rose-300'
                  : 'bg-slate-800 text-slate-400'
              }`}
            >
              {inc.priorityScore}
            </span>
          </button>
        ))}
      </div>

      {/* Incident Master Header */}
      <div className="bg-slate-900/95 border border-slate-800 rounded-lg p-5 shadow-defence">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="font-mono text-sm font-bold text-sky-400">
                {incident.id}
              </span>
              <span
                className={`text-2xs font-bold px-2 py-0.5 rounded font-mono ${
                  incident.severity === 'CRITICAL'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                }`}
              >
                {incident.severity}
              </span>
              <span className="text-2xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                {incident.status}
              </span>
            </div>

            <h1 className="text-base font-bold text-white leading-snug">
              {incident.title}
            </h1>
            <p className="text-xs text-slate-400 mt-1">
              {incident.threatType} • Attributed Threat Actor:{' '}
              <strong className="text-slate-200">{incident.attribution}</strong>
            </p>
          </div>

          {/* Priority Score Gauge */}
          <div className="flex items-center gap-6 bg-slate-950/80 border border-slate-800 rounded-lg px-4 py-3">
            <div className="text-center">
              <div className="text-2xs text-slate-400 uppercase font-semibold">Priority Score</div>
              <div className="text-2xl font-black font-mono text-rose-400 mt-0.5 leading-none">
                <AnimatedCounter value={incident.priorityScore} />
                <span className="text-xs text-slate-500 font-normal">/100</span>
              </div>
            </div>

            <div className="h-8 w-px bg-slate-800" />

            <div className="text-center">
              <div className="text-2xs text-slate-400 uppercase font-semibold">Confidence</div>
              <div className="text-2xl font-black font-mono text-sky-400 mt-0.5 leading-none">
                <AnimatedCounter value={incident.confidence} suffix="%" />
              </div>
            </div>

            <div className="h-8 w-px bg-slate-800" />

            <div className="text-center">
              <div className="text-2xs text-slate-400 uppercase font-semibold">Sources</div>
              <div className="text-2xl font-black font-mono text-indigo-400 mt-0.5 leading-none">
                {incident.sourcesCount}
              </div>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 mt-4 overflow-x-auto scrollbar-none border-b border-slate-800/80 pb-2">
          {TABS.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-semibold transition-all shrink-0 ${
                  isActive
                    ? 'bg-sky-500/20 text-sky-300 border border-sky-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent'
                }`}
              >
                <Icon className="w-3.5 h-3.5 text-sky-400" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Content Panes */}
      <AnimatePresence mode="wait">
        {activeTab === 'evidence' && (
          <motion.div
            key="evidence"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.2 }}
            className="grid grid-cols-1 lg:grid-cols-2 gap-4"
          >
            {/* Correlation Evidence Chain */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-1 flex items-center gap-2">
                <Layers className="w-3.5 h-3.5 text-indigo-400" />
                Cross-Source Telemetry Evidence
              </h3>
              <p className="text-xs text-slate-400 mb-3">
                Multi-sensor corroboration eliminating isolated false alarms.
              </p>

              <div className="space-y-2">
                {bluf.evidence.map((ev, i) => (
                  <div
                    key={i}
                    className="p-2.5 rounded bg-slate-950 border border-slate-800/90 text-xs text-slate-200 flex items-start gap-2"
                  >
                    <CheckCircle2 className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
                    <span className="leading-relaxed">{ev}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* MITRE Chain & Kill-Chain Alignment */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence flex flex-col justify-between">
              <div>
                <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-1 flex items-center gap-2">
                  <ShieldAlert className="w-3.5 h-3.5 text-purple-400" />
                  MITRE ATT&CK Execution Chain
                </h3>
                <p className="text-xs text-slate-400 mb-3">
                  Standardized adversary tactics identified across the kill-chain.
                </p>

                <div className="space-y-2">
                  {bluf.mitreMapping.map((m) => (
                    <div
                      key={m.id}
                      className="p-2.5 rounded bg-slate-950 border border-slate-800/90 text-xs flex items-center justify-between"
                    >
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-2xs px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 font-bold">
                          {m.id}
                        </span>
                        <span className="font-semibold text-white">{m.name}</span>
                      </div>
                      <span className="text-2xs font-mono text-emerald-400">CONFIRMED</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800">
                <div className="text-2xs font-bold uppercase tracking-wider text-rose-400 mb-1">
                  Bottom Line Summary
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {bluf.bottomLine}
                </p>
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'timeline' && (
          <motion.div
            key="timeline"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.2 }}
            className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence"
          >
            <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-2">
              <Clock className="w-4 h-4 text-sky-400" />
              Chronological Sensor Ingress Sequence
            </h3>
            <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800 mt-4">
              {incident.timeline?.map((item, idx) => (
                <div key={idx} className="relative group">
                  <span className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full border-2 border-slate-950 bg-sky-400" />
                  <div className="bg-slate-950 border border-slate-800 rounded p-3 text-xs">
                    <div className="flex items-center justify-between text-2xs mb-1">
                      <span className="font-mono font-bold text-sky-400">{item.time}</span>
                      <span className="font-mono text-slate-400 px-1.5 py-0.2 rounded bg-slate-800">
                        {item.source}
                      </span>
                    </div>
                    <div className="text-slate-200 font-medium">{item.event}</div>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        )}

        {activeTab === 'assets' && (
          <motion.div
            key="assets"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.2 }}
            className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence space-y-4"
          >
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Server className="w-3.5 h-3.5 text-sky-400" />
              Affected Enclave Assets &amp; Quarantine Controls
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {incident.affectedAssets?.map((asset) => {
                const isIsolated = asset.status.includes('Isolated');
                return (
                  <div
                    key={asset.id}
                    className="bg-slate-950 border border-slate-800 rounded-lg p-3.5 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between text-2xs mb-1">
                        <span className="font-mono font-bold text-white">{asset.id}</span>
                        <span
                          className={`font-semibold text-[10px] px-1.5 py-0.2 rounded ${
                            isIsolated
                              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                              : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          }`}
                        >
                          {asset.status}
                        </span>
                      </div>
                      <div className="text-xs font-medium text-slate-300">{asset.role}</div>
                      <div className="text-[11px] font-mono text-sky-400 mt-0.5">IP: {asset.ip}</div>
                      <div className="text-[11px] text-slate-400 mt-1">
                        Exposure: <span className="text-slate-300">{asset.exposure}</span>
                      </div>
                    </div>

                    <div className="mt-3 pt-2 border-t border-slate-800">
                      <button
                        onClick={() => isolateAsset(incident.id, asset.id)}
                        disabled={isIsolated}
                        className={`w-full py-1.5 rounded text-2xs font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 transition-colors ${
                          isIsolated
                            ? 'bg-slate-800 text-slate-400 cursor-not-allowed'
                            : 'bg-rose-600 hover:bg-rose-500 text-white shadow-sm'
                        }`}
                      >
                        <Lock className="w-3 h-3" />
                        {isIsolated ? 'Quarantined' : 'Quarantine Asset'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </motion.div>
        )}

        {activeTab === 'blast_radius' && (
          <motion.div
            key="blast_radius"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.2 }}
            className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence space-y-4"
          >
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Network className="w-3.5 h-3.5 text-rose-400" />
              Subnet Blast Radius &amp; Exposure Analysis
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="bg-slate-950 border border-slate-800 rounded p-4 space-y-2">
                <div className="text-2xs font-bold text-rose-400 uppercase">Directly Compromised Zone</div>
                <div className="font-mono text-sm text-white font-bold">10.42.1.0/24 (Command Subnet)</div>
                <p className="text-slate-300 text-xs">
                  Active LSASS injection and C2 beaconing. Cryptographic quarantine isolates this subnet from broader operational networks.
                </p>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded p-4 space-y-2">
                <div className="text-2xs font-bold text-amber-400 uppercase">Elevated Exposure Subnet</div>
                <div className="font-mono text-sm text-white font-bold">10.42.3.0/24 (Database Core)</div>
                <p className="text-slate-300 text-xs">
                  Probed via SMB lateral scan. Gateway enforcement has severed inbound RPC pipes to protect data integrity.
                </p>
              </div>
            </div>
          </motion.div>
        )}

        {activeTab === 'historical' && (
          <motion.div
            key="historical"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.2 }}
            className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence space-y-3"
          >
            <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <History className="w-3.5 h-3.5 text-sky-400" />
              Similar Historical Campaigns &amp; Signatures
            </h3>
            <div className="space-y-2 text-xs">
              <div className="bg-slate-950 border border-slate-800 rounded p-3 flex justify-between items-center">
                <div>
                  <div className="font-bold text-white">Campaign PolarStorm (2024-Q3)</div>
                  <div className="text-slate-400 text-2xs mt-0.5">Matched JA3 TLS Beaconing &amp; MiniDumpWriteDump LSASS injection.</div>
                </div>
                <span className="font-mono font-bold text-sky-400">94.8% Similarity</span>
              </div>
              <div className="bg-slate-950 border border-slate-800 rounded p-3 flex justify-between items-center">
                <div>
                  <div className="font-bold text-white">Operation GhostPulse (2025-Q1)</div>
                  <div className="text-slate-400 text-2xs mt-0.5">Identical C2 destination IP block 185.220.101.0/24.</div>
                </div>
                <span className="font-mono font-bold text-emerald-400">98.2% Similarity</span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
