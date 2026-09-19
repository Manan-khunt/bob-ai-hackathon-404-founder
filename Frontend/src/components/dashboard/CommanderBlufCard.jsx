import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileText,
  Copy,
  Download,
  Check,
  ShieldAlert,
  Sparkles,
  Lock,
  RefreshCw,
  Cpu,
  Layers,
} from 'lucide-react';
import { useAppStore } from '../../store';
import AnimatedCounter from '../common/AnimatedCounter';

const SYNTHESIS_STEPS = [
  'ANALYZING EVIDENCE...',
  'CORRELATING SOURCES...',
  'MAPPING MITRE...',
  'GENERATING COMMANDER BRIEF...',
];

export default function CommanderBlufCard() {
  const selectedIncidentId = useAppStore((s) => s.selectedIncidentId);
  const incidents = useAppStore((s) => s.incidents);
  const isolateAsset = useAppStore((s) => s.isolateAsset);

  const [copied, setCopied] = useState(false);
  const [isolated, setIsolated] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationStepIndex, setGenerationStepIndex] = useState(0);

  const incident =
    incidents.find((i) => i.id === selectedIncidentId) || incidents[0];
  const bluf = incident.bluf;

  const handleGenerateBluf = () => {
    setIsGenerating(true);
    setGenerationStepIndex(0);

    const stepInterval = setInterval(() => {
      setGenerationStepIndex((prev) => {
        if (prev < SYNTHESIS_STEPS.length - 1) {
          return prev + 1;
        } else {
          clearInterval(stepInterval);
          setTimeout(() => setIsGenerating(false), 350);
          return prev;
        }
      });
    }, 450);
  };

  const handleCopy = () => {
    const text = `COMMANDER BLUF // ${incident.id}\nPRIORITY: ${bluf.priorityScore}/100 (${bluf.priorityLevel})\n\nBOTTOM LINE:\n${bluf.bottomLine}\n\nOPERATIONAL IMPACT:\n${bluf.impact}\n\nEVIDENCE:\n${bluf.evidence.join('\n')}\n\nRECOMMENDED ACTION:\n${bluf.recommendedAction}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExport = () => {
    const text = `IMMUNE-NET // EXECUTIVE INTELLIGENCE BRIEF\nIncident ID: ${incident.id}\nAttribution: ${incident.attribution}\nPriority: ${bluf.priorityScore}/100\nDate: ${new Date().toISOString()}\n\nBOTTOM LINE:\n${bluf.bottomLine}\n\nIMPACT:\n${bluf.impact}\n\nRECOMMENDED ACTION:\n${bluf.recommendedAction}`;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `BLUF-${incident.id}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleIsolateAll = () => {
    incident.affectedAssets.forEach((a) => {
      isolateAsset(incident.id, a.id);
    });
    setIsolated(true);
    setTimeout(() => setIsolated(false), 3000);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, ease: 'easeOut' }}
      className="bg-slate-900/95 border-2 border-sky-500/40 rounded-lg p-5 shadow-defence relative overflow-hidden select-none"
    >
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            <h2 className="text-xs font-bold text-white uppercase tracking-wider">
              COMMANDER BLUF (BOTTOM LINE UP FRONT)
            </h2>
            <span className="text-2xs font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
              PRIORITY <AnimatedCounter value={bluf.priorityScore} duration={800} />/100 • {bluf.priorityLevel}
            </span>
          </div>
          <div className="text-xs text-slate-400 mt-0.5 font-mono">
            Target Incident: <strong className="text-sky-400">{incident.id}</strong> — {incident.title}
          </div>
        </div>

        {/* Action buttons with [GENERATE BLUF] */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleGenerateBluf}
            disabled={isGenerating}
            className={`px-3 py-1.5 rounded text-xs font-bold uppercase tracking-wider flex items-center gap-1.5 transition-all border ${
              isGenerating
                ? 'bg-sky-500/20 text-sky-300 border-sky-500/40'
                : 'bg-sky-600 hover:bg-sky-500 text-white border-transparent shadow-sm shadow-sky-900/50'
            }`}
          >
            <Sparkles className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />
            <span>{isGenerating ? SYNTHESIS_STEPS[generationStepIndex] : 'Generate BLUF'}</span>
          </button>

          <button
            onClick={handleCopy}
            className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors border border-slate-700"
            title="Copy formatted brief"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>

          <button
            onClick={handleExport}
            className="px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1.5 transition-colors border border-slate-700"
            title="Export brief to file"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export</span>
          </button>
        </div>
      </div>

      {/* BLUF Staged Sequential Reveal Content */}
      <AnimatePresence mode="wait">
        {!isGenerating ? (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Left 2 Cols: Sequential Reveal */}
            <div className="lg:col-span-2 space-y-3">
              {/* Step 1: Bottom Line */}
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25, delay: 0.05 }}
                className="bg-slate-950/80 border border-slate-800/90 rounded p-3.5"
              >
                <div className="text-2xs font-bold uppercase tracking-wider text-sky-400 mb-1 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                  1. Bottom Line
                </div>
                <p className="text-xs text-slate-100 font-medium leading-relaxed">
                  {bluf.bottomLine}
                </p>
              </motion.div>

              {/* Step 2: Operational Impact */}
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25, delay: 0.12 }}
                className="bg-slate-950/80 border border-slate-800/90 rounded p-3.5"
              >
                <div className="text-2xs font-bold uppercase tracking-wider text-amber-400 mb-1 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                  2. Operational Impact
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {bluf.impact}
                </p>
              </motion.div>

              {/* Step 3: Multi-Source Evidence Chain */}
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25, delay: 0.18 }}
                className="bg-slate-950/80 border border-slate-800/90 rounded p-3.5"
              >
                <div className="text-2xs font-bold uppercase tracking-wider text-indigo-400 mb-1 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
                  3. Multi-Source Evidence Chain
                </div>
                <ul className="space-y-1 mt-1 text-xs text-slate-300">
                  {bluf.evidence.map((ev, i) => (
                    <motion.li
                      key={i}
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.2, delay: 0.22 + i * 0.05 }}
                      className="flex items-start gap-2"
                    >
                      <span className="text-sky-400 text-xs font-mono">•</span>
                      <span>{ev}</span>
                    </motion.li>
                  ))}
                </ul>
              </motion.div>
            </div>

            {/* Right Col: MITRE & Decision Action */}
            <div className="space-y-3 flex flex-col justify-between">
              {/* Step 4: Associated MITRE */}
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25, delay: 0.26 }}
                className="bg-slate-950/80 border border-slate-800/90 rounded p-3.5"
              >
                <div className="text-2xs font-bold uppercase tracking-wider text-purple-400 mb-2 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                  4. Associated MITRE ATT&CK
                </div>
                <div className="space-y-1.5">
                  {bluf.mitreMapping.map((m, idx) => (
                    <motion.div
                      key={m.id}
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ duration: 0.2, delay: 0.28 + idx * 0.05 }}
                      className="text-xs flex items-center gap-2"
                    >
                      <span className="font-mono text-2xs px-1.5 py-0.2 rounded bg-purple-950 border border-purple-800 text-purple-300 font-bold">
                        {m.id}
                      </span>
                      <span className="text-slate-300 text-[11px] truncate">{m.name}</span>
                    </motion.div>
                  ))}
                </div>
              </motion.div>

              {/* Step 5: Recommended Commander Action */}
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.25, delay: 0.35 }}
                className="bg-rose-950/20 border border-rose-800/60 rounded-lg p-3.5 shadow-sm"
              >
                <div className="text-2xs font-bold uppercase tracking-wider text-rose-400 mb-1 flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  5. Recommended Commander Action
                </div>
                <p className="text-xs text-slate-200 font-medium leading-relaxed mb-3">
                  {bluf.recommendedAction}
                </p>

                <button
                  onClick={handleIsolateAll}
                  disabled={isolated}
                  className={`w-full py-2 px-3 rounded text-xs font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition-all shadow-md active:scale-98 ${
                    isolated
                      ? 'bg-emerald-600 text-white'
                      : 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-950/50'
                  }`}
                >
                  <Lock className="w-3.5 h-3.5" />
                  {isolated ? 'Isolation Dispatched Successfully' : 'Authorize Node Cryptographic Isolation'}
                </button>
              </motion.div>
            </div>
          </div>
        ) : (
          /* Real-time Synthesis Loading Animation */
          <div className="py-12 flex flex-col items-center justify-center text-center space-y-3">
            <div className="w-10 h-10 rounded-full bg-sky-500/20 border border-sky-500/50 flex items-center justify-center text-sky-400 animate-spin">
              <Cpu className="w-5 h-5" />
            </div>
            <div className="font-mono text-xs font-bold tracking-wider text-sky-300 uppercase animate-pulse">
              {SYNTHESIS_STEPS[generationStepIndex]}
            </div>
            <div className="text-[11px] text-slate-400 font-mono">
              Fusing telemetry across SIEM, Sensors, Endpoint, and Threat Intel
            </div>
          </div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
