import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ChevronRight, AlertCircle, Check } from 'lucide-react';
import { MITRE_TACTICS } from '../../data/demoData';

export default function MitreAttackPanel() {
  const navigate = useNavigate();

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-sky-400" />
          <h3 className="text-xs font-bold text-white uppercase tracking-wider">
            MITRE ATT&CK ADVERSARY TECHNIQUES
          </h3>
        </div>
        <button
          onClick={() => navigate('/mitre')}
          className="text-2xs font-semibold text-sky-400 hover:text-sky-300 flex items-center gap-1"
        >
          View Full Matrix
          <ChevronRight className="w-3 h-3" />
        </button>
      </div>
      <p className="text-xs text-slate-400 mb-4">
        Observed tactics mapped directly against the standardized enterprise threat framework.
      </p>

      {/* Tactic Columns Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {MITRE_TACTICS.slice(2, 6).map((tactic) => (
          <div
            key={tactic.id}
            className="bg-slate-950 border border-slate-800/90 rounded p-3 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-2xs font-mono font-bold text-sky-400">
                  {tactic.id}
                </span>
                <span className="text-[10px] uppercase font-semibold text-slate-400">
                  {tactic.techniques.filter((t) => t.active).length} Active
                </span>
              </div>
              <h4 className="text-xs font-bold text-white mb-2 truncate">
                {tactic.name}
              </h4>
            </div>

            <div className="space-y-1.5 mt-1">
              {tactic.techniques.map((tech) => (
                <div
                  key={tech.id}
                  onClick={() => navigate('/mitre')}
                  className={`p-2 rounded border cursor-pointer transition-all ${
                    tech.active
                      ? 'bg-rose-950/20 border-rose-800/40 hover:border-rose-600/60'
                      : 'bg-slate-900/40 border-slate-800/60 text-slate-400'
                  }`}
                >
                  <div className="flex items-center justify-between text-2xs mb-0.5 font-mono">
                    <span className={tech.active ? 'text-rose-300 font-bold' : 'text-slate-400'}>
                      {tech.id}
                    </span>
                    {tech.active && (
                      <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                    )}
                  </div>
                  <div className="text-[11px] font-medium text-slate-200 truncate">
                    {tech.name}
                  </div>
                  {tech.incidents?.length > 0 && (
                    <div className="text-[10px] text-slate-400 mt-1 font-mono">
                      Observed: {tech.incidents.join(', ')}
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
