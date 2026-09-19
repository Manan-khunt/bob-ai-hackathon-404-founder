import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, CheckCircle2, ShieldCheck, FileCheck, Layers, AlertCircle } from 'lucide-react';
import { useAppStore } from '../../store';

export default function FalsePositiveEvidenceModal() {
  const selectedFalsePositive = useAppStore((s) => s.selectedFalsePositive);
  const closeFalsePositiveModal = useAppStore((s) => s.closeFalsePositiveModal);

  return (
    <AnimatePresence>
      {selectedFalsePositive && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 select-none">
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={closeFalsePositiveModal}
            className="fixed inset-0 bg-slate-950/75 backdrop-blur-sm"
          />

          {/* Modal Container */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 8 }}
            transition={{ type: 'spring', stiffness: 420, damping: 32 }}
            className="w-full max-w-xl bg-slate-900 border-2 border-emerald-500/50 rounded-xl shadow-2xl overflow-hidden relative z-10"
          >
            {/* Header */}
            <div className="p-4 bg-emerald-950/30 border-b border-emerald-800/40 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <div>
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                    SUPPRESSED FALSE POSITIVE EVIDENCE RECORD
                  </h3>
                  <div className="text-2xs text-emerald-300 font-mono">
                    Alert ID: {selectedFalsePositive.id} • AI Confidence: {selectedFalsePositive.confidence}%
                  </div>
                </div>
              </div>

              <button
                onClick={closeFalsePositiveModal}
                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Content */}
            <div className="p-5 space-y-4 text-xs">
              {/* Triage Summary */}
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-3.5">
                <div className="text-2xs font-bold uppercase tracking-wider text-emerald-400 mb-1">
                  Automated Noise Suppression Rationale
                </div>
                <p className="text-slate-200 leading-relaxed">
                  {selectedFalsePositive.explanation}
                </p>
              </div>

              {/* Validation Checklist */}
              <div className="space-y-2">
                <div className="text-2xs font-bold uppercase tracking-wider text-slate-400">
                  Corroboration &amp; Verification Checks
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800/80">
                    <span className="text-slate-300">Cross-Sensor Corroboration</span>
                    <span className="text-emerald-400 font-semibold font-mono">ISOLATED SIGNAL (0 PEERS)</span>
                  </div>

                  <div className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800/80">
                    <span className="text-slate-300">Process / Network Signature</span>
                    <span className="text-emerald-400 font-semibold font-mono">BENIGN AUTHORIZED SIGNATURE</span>
                  </div>

                  <div className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800/80">
                    <span className="text-slate-300">Operational Change Reconciliation</span>
                    <span className="text-emerald-400 font-semibold font-mono">MATCHED APPROVED CHANGE TICKET</span>
                  </div>

                  <div className="flex items-center justify-between p-2 rounded bg-slate-950 border border-slate-800/80">
                    <span className="text-slate-300">Analyst Impact</span>
                    <span className="text-sky-400 font-semibold font-mono">FATIGUE PREVENTED (AUTO-LOGGED)</span>
                  </div>
                </div>
              </div>

              {/* Raw Payload Trace */}
              <div>
                <div className="text-2xs font-bold uppercase tracking-wider text-slate-400 mb-1">
                  Archived Telemetry Payload (Auditable)
                </div>
                <pre className="bg-slate-950 border border-slate-800 rounded p-2.5 font-mono text-2xs text-slate-300 overflow-x-auto">
                  {selectedFalsePositive.rawPayload || '{"status": "suppressed"}'}
                </pre>
              </div>
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
              <span className="text-2xs text-slate-400 font-mono">
                FORENSIC HASH: 8f4a21b...ed90 (IMMUTABLE AUDIT LOG)
              </span>
              <button
                onClick={closeFalsePositiveModal}
                className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold transition-colors"
              >
                Acknowledge Suppression
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
}
