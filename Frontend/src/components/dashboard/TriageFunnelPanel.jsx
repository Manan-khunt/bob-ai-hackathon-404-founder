import React from 'react';
import { Filter, ArrowDown, CheckCircle2, ShieldAlert, AlertTriangle, Sparkles } from 'lucide-react';
import { useAppStore } from '../../store';

const FUNNEL_STAGES = [
  { label: 'RAW ALERTS INGESTED', count: '1,284', pct: '100%', color: 'bg-slate-700 text-slate-200' },
  { label: 'CROSS-SOURCE CORRELATED', count: '214', pct: '16.6%', color: 'bg-indigo-600/60 text-indigo-200' },
  { label: 'SIGNIFICANT INCIDENTS', count: '47', pct: '3.6%', color: 'bg-sky-600/70 text-sky-100' },
  { label: 'TRUE THREATS CONFIRMED', count: '19', pct: '1.4%', color: 'bg-amber-600/80 text-amber-100' },
  { label: 'CRITICAL DEFENCE ACTIONS', count: '6', pct: '0.4%', color: 'bg-rose-600 text-white font-bold' },
];

export default function TriageFunnelPanel() {
  const metrics = useAppStore((s) => s.metrics);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence flex flex-col justify-between">
      {/* Header */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-sky-400" />
            <h3 className="text-xs font-bold text-white uppercase tracking-wider">
              AI TRIAGE & NOISE REDUCTION FUNNEL
            </h3>
          </div>
          <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
            SIMULATED BENCHMARK
          </span>
        </div>
        <p className="text-xs text-slate-400 mb-4">
          Visual reduction of 1,284 incoming alerts into 6 actionable commander priorities.
        </p>

        {/* Funnel visualization */}
        <div className="space-y-2">
          {FUNNEL_STAGES.map((stage, idx) => (
            <div key={stage.label} className="relative">
              <div className="flex items-center justify-between text-2xs mb-1 px-1 font-semibold">
                <span className="text-slate-300">{stage.label}</span>
                <span className="font-mono text-white">{stage.count} ({stage.pct})</span>
              </div>
              <div className="h-4 bg-slate-950 rounded overflow-hidden border border-slate-800">
                <div
                  className={`h-full rounded transition-all duration-500 ${stage.color}`}
                  style={{
                    width: `${Math.max(8, 100 - idx * 22)}%`,
                  }}
                />
              </div>
              {idx < FUNNEL_STAGES.length - 1 && (
                <div className="flex justify-center my-0.5">
                  <ArrowDown className="w-3 h-3 text-slate-600" />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Reduction Metrics Highlight */}
      <div className="grid grid-cols-2 gap-3 mt-5 pt-4 border-t border-slate-800">
        <div className="bg-emerald-950/20 border border-emerald-800/40 rounded-lg p-3">
          <div className="flex items-center gap-1.5 text-emerald-400 text-2xs font-bold uppercase mb-1">
            <CheckCircle2 className="w-3.5 h-3.5" />
            False Positive Suppression
          </div>
          <div className="text-2xl font-extrabold text-emerald-300 font-mono">
            {metrics.falsePositiveReductionPct}%
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            1,147 benign signals suppressed automatically without manual review.
          </div>
        </div>

        <div className="bg-sky-950/20 border border-sky-800/40 rounded-lg p-3">
          <div className="flex items-center gap-1.5 text-sky-400 text-2xs font-bold uppercase mb-1">
            <Sparkles className="w-3.5 h-3.5" />
            Analyst Workload Relieved
          </div>
          <div className="text-2xl font-extrabold text-sky-300 font-mono">
            {metrics.analystWorkloadReductionPct}%
          </div>
          <div className="text-[11px] text-slate-400 mt-0.5">
            Command decisions delivered in minutes instead of manual multi-hour triage.
          </div>
        </div>
      </div>
    </div>
  );
}
