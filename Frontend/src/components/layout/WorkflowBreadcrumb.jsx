import React from 'react';
import { ArrowRight, Database, Filter, GitMerge, CheckCircle, AlertTriangle, Shield, FileText, CheckCheck } from 'lucide-react';

const WORKFLOW_STEPS = [
  { id: 'ingest', label: 'INGEST', desc: '8 Sources', icon: Database },
  { id: 'normalize', label: 'NORMALIZE', desc: 'JSON/CEF/STIX', icon: Filter },
  { id: 'correlate', label: 'CORRELATE', desc: 'Topology & Time', icon: GitMerge },
  { id: 'triage', label: 'TRIAGE', desc: 'True vs False Pos', icon: CheckCircle },
  { id: 'prioritize', label: 'PRIORITIZE', desc: '0-100 Score', icon: AlertTriangle },
  { id: 'mitre', label: 'MITRE ATT&CK', desc: 'Tactics & Techniques', icon: Shield },
  { id: 'bluf', label: 'BLUF', desc: 'Executive Brief', icon: FileText },
  { id: 'decision', label: 'DECISION', desc: 'Command Isolation', icon: CheckCheck },
];

export default function WorkflowBreadcrumb({ activeStep = 'prioritize' }) {
  return (
    <div className="bg-slate-900/80 border-b border-slate-800/80 px-4 py-2.5">
      <div className="flex items-center justify-between overflow-x-auto scrollbar-none gap-2 min-w-max">
        <div className="flex items-center gap-1 text-2xs uppercase tracking-widest text-sky-400 font-semibold mr-2 select-none">
          <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse" />
          Intelligence Pipeline
        </div>

        <div className="flex items-center gap-1.5 flex-1">
          {WORKFLOW_STEPS.map((step, idx) => {
            const Icon = step.icon;
            const isLast = idx === WORKFLOW_STEPS.length - 1;
            return (
              <React.Fragment key={step.id}>
                <div
                  className={`flex items-center gap-2 px-2.5 py-1 rounded border text-xs transition-all ${
                    step.id === activeStep
                      ? 'bg-sky-500/15 border-sky-500/40 text-sky-200 font-medium'
                      : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-300 hover:border-slate-700'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                  <div className="leading-tight">
                    <span className="font-semibold tracking-wider text-2xs block">{step.label}</span>
                    <span className="text-[10px] text-slate-500 block leading-none">{step.desc}</span>
                  </div>
                </div>

                {!isLast && (
                  <ArrowRight className="w-3 h-3 text-slate-600 shrink-0 mx-0.5" />
                )}
              </React.Fragment>
            );
          })}
        </div>

        <div className="text-2xs font-mono text-slate-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800 whitespace-nowrap ml-2">
          MTTD: <span className="text-emerald-400 font-semibold">14.8s</span> | MTTR: <span className="text-sky-400 font-semibold">42.0s</span>
        </div>
      </div>
    </div>
  );
}
