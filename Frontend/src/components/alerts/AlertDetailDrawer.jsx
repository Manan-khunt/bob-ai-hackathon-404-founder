import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Server,
  Layers,
  Sparkles,
  ExternalLink,
} from 'lucide-react';
import { useAppStore } from '../../store';

export default function AlertDetailDrawer() {
  const selectedAlert = useAppStore((s) => s.selectedAlert);
  const closeAlertDrawer = useAppStore((s) => s.closeAlertDrawer);
  const selectIncident = useAppStore((s) => s.selectIncident);

  const isTrueThreat = selectedAlert?.classification === 'TRUE_THREAT';
  const isFP = selectedAlert?.classification === 'FALSE_POSITIVE';

  return (
    <AnimatePresence>
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex justify-end">
          {/* Backdrop Blur */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={closeAlertDrawer}
            className="fixed inset-0 bg-slate-950/70 backdrop-blur-sm"
          />

          {/* Drawer Sheet */}
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', stiffness: 380, damping: 32 }}
            className="w-full max-w-lg bg-slate-900 border-l border-slate-800 h-full flex flex-col justify-between shadow-2xl overflow-y-auto relative z-10"
          >
            {/* Drawer Header */}
            <div>
              <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/70 sticky top-0 z-10 select-none">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-sky-400">
                      {selectedAlert.id}
                    </span>
                    <span className="font-mono text-2xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-semibold">
                      {selectedAlert.source}
                    </span>
                  </div>
                  <div className="text-2xs text-slate-400 mt-0.5">
                    Detailed Telemetry Inspection &amp; Explainability
                  </div>
                </div>

                <button
                  onClick={closeAlertDrawer}
                  className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {/* Drawer Body */}
              <div className="p-5 space-y-4">
                {/* Explainability Callout */}
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 }}
                  className={`p-4 rounded-lg border ${
                    isTrueThreat
                      ? 'bg-rose-950/20 border-rose-800/50 text-rose-200'
                      : isFP
                      ? 'bg-emerald-950/20 border-emerald-800/50 text-emerald-200'
                      : 'bg-amber-950/20 border-amber-800/50 text-amber-200'
                  }`}
                >
                  <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider mb-1">
                    <Sparkles className="w-3.5 h-3.5" />
                    Why was this classified this way?
                  </div>
                  <p className="text-xs leading-relaxed text-slate-200">
                    {selectedAlert.explanation}
                  </p>
                </motion.div>

                {/* Core Attributes Grid */}
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.16 }}
                  className="grid grid-cols-2 gap-3 bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 text-xs"
                >
                  <div>
                    <span className="text-2xs text-slate-400 uppercase font-semibold">Classification</span>
                    <div className="font-bold text-white mt-0.5 flex items-center gap-1">
                      {isTrueThreat && <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />}
                      {isFP && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                      {selectedAlert.classification}
                    </div>
                  </div>

                  <div>
                    <span className="text-2xs text-slate-400 uppercase font-semibold">Confidence</span>
                    <div className="font-mono font-bold text-white mt-0.5">
                      {selectedAlert.confidence}%
                    </div>
                  </div>

                  <div>
                    <span className="text-2xs text-slate-400 uppercase font-semibold">Correlated Incident</span>
                    <div className="font-mono font-bold text-sky-400 mt-0.5 hover:underline cursor-pointer">
                      {selectedAlert.incidentId || 'UNASSOCIATED'}
                    </div>
                  </div>

                  <div>
                    <span className="text-2xs text-slate-400 uppercase font-semibold">Timestamp</span>
                    <div className="font-mono text-slate-300 mt-0.5">
                      {selectedAlert.timestamp}
                    </div>
                  </div>
                </motion.div>

                {/* Target Asset Details */}
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.22 }}
                  className="bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 text-xs"
                >
                  <span className="text-2xs text-slate-400 uppercase font-semibold">Target Operational Asset</span>
                  <div className="font-bold text-white text-sm mt-0.5">{selectedAlert.asset}</div>
                  <div className="font-mono text-2xs text-sky-400 mt-0.5">IP: {selectedAlert.assetIp}</div>
                </motion.div>

                {/* Event Details */}
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.28 }}
                  className="space-y-2"
                >
                  <span className="text-2xs text-slate-400 uppercase font-semibold">Normalized Event Name</span>
                  <div className="bg-slate-950 border border-slate-800 rounded p-2.5 text-xs font-semibold text-white">
                    {selectedAlert.normalizedEvent}
                  </div>

                  <span className="text-2xs text-slate-400 uppercase font-semibold">Raw Ingested Event</span>
                  <div className="bg-slate-950 border border-slate-800 rounded p-2.5 text-xs text-slate-300">
                    {selectedAlert.event}
                  </div>

                  {/* Raw JSON Payload */}
                  {selectedAlert.rawPayload && (
                    <div>
                      <span className="text-2xs text-slate-400 uppercase font-semibold">Raw Sensor Payload (JSON)</span>
                      <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 text-2xs font-mono text-sky-300 overflow-x-auto mt-1">
                        {selectedAlert.rawPayload}
                      </pre>
                    </div>
                  )}
                </motion.div>

                {/* MITRE Mapping */}
                {selectedAlert.mitre && (
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.34 }}
                    className="bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 text-xs"
                  >
                    <span className="text-2xs text-slate-400 uppercase font-semibold">MITRE ATT&CK Mapping</span>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-sky-950 border border-sky-800 text-sky-300">
                        {selectedAlert.mitre}
                      </span>
                      <span className="font-medium text-slate-200 text-xs">
                        {selectedAlert.mitreName}
                      </span>
                    </div>
                  </motion.div>
                )}
              </div>
            </div>

            {/* Drawer Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/70 flex items-center justify-between">
              <button
                onClick={closeAlertDrawer}
                className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors"
              >
                Close Drawer
              </button>

              {selectedAlert.incidentId && (
                <button
                  onClick={() => {
                    selectIncident(selectedAlert.incidentId);
                    closeAlertDrawer();
                  }}
                  className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors"
                >
                  <span>Inspect Parent Incident</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
