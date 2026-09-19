import React from 'react';
import { Shield, ExternalLink, CheckCircle2, AlertTriangle } from 'lucide-react';
import { MITRE_TACTICS } from '../data/demoData';

export default function MitrePage() {
  return (
    <div className="space-y-6 max-w-[1700px] mx-auto pb-12">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence">
        <div className="flex items-center gap-2 mb-1">
          <Shield className="w-5 h-5 text-sky-400" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            MITRE ATT&CK ENTERPRISE THREAT MATRIX
          </h2>
        </div>
        <p className="text-xs text-slate-400">
          Adversary tactics and techniques observed across correlated multi-source threat intelligence.
        </p>
      </div>

      {/* Full Matrix Columns */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
        {MITRE_TACTICS.map((tactic) => (
          <div
            key={tactic.id}
            className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between text-2xs mb-1">
                <span className="font-mono font-bold text-sky-400">{tactic.id}</span>
                <span className="text-slate-400 font-semibold font-mono text-[10px]">
                  {tactic.techniques.filter((t) => t.active).length} OBSERVED
                </span>
              </div>
              <h3 className="text-xs font-bold text-white mb-3">{tactic.name}</h3>
            </div>

            <div className="space-y-2">
              {tactic.techniques.map((tech) => (
                <div
                  key={tech.id}
                  className={`p-2.5 rounded border ${
                    tech.active
                      ? 'bg-rose-950/20 border-rose-800/60 shadow-sm'
                      : 'bg-slate-950/40 border-slate-800/80 text-slate-400'
                  }`}
                >
                  <div className="flex items-center justify-between text-2xs mb-1">
                    <span className={`font-mono font-bold ${tech.active ? 'text-rose-300' : 'text-slate-400'}`}>
                      {tech.id}
                    </span>
                    {tech.active && (
                      <span className="text-[9px] uppercase px-1 rounded bg-rose-500/20 text-rose-300 font-bold">
                        ACTIVE
                      </span>
                    )}
                  </div>

                  <div className="text-xs font-semibold text-slate-200">{tech.name}</div>

                  {tech.incidents?.length > 0 && (
                    <div className="mt-2 pt-1.5 border-t border-slate-800/80 text-[10px] font-mono text-slate-400">
                      Observed in: <strong className="text-slate-300">{tech.incidents.join(', ')}</strong>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
