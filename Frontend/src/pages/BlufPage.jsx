import React from 'react';
import CommanderBlufCard from '../components/dashboard/CommanderBlufCard';
import { FileSpreadsheet, ShieldAlert, CheckCheck, Clock } from 'lucide-react';
import { useAppStore } from '../store';

export default function BlufPage() {
  const incidents = useAppStore((s) => s.incidents);
  const selectIncident = useAppStore((s) => s.selectIncident);
  const selectedIncidentId = useAppStore((s) => s.selectedIncidentId);

  return (
    <div className="space-y-6 max-w-[1700px] mx-auto pb-12">
      {/* Header Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <FileSpreadsheet className="w-5 h-5 text-sky-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              COMMANDER'S OPERATIONAL BRIEFING ROOM (BLUF)
            </h2>
          </div>
          <p className="text-xs text-slate-400">
            Synthesized decision-grade intelligence summaries designed for executive understanding in under 60 seconds.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-2xs font-mono text-slate-400">
            Total Briefings: <strong className="text-white">{incidents.length}</strong>
          </span>
        </div>
      </div>

      {/* Primary Selected Incident BLUF */}
      <CommanderBlufCard />

      {/* Grid of All Other Incident Briefings */}
      <div className="space-y-3">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider">
          All Incident Briefing Summaries
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {incidents.map((inc) => (
            <div
              key={inc.id}
              onClick={() => selectIncident(inc.id)}
              className={`p-4 rounded-lg border cursor-pointer transition-all ${
                selectedIncidentId === inc.id
                  ? 'bg-sky-500/10 border-sky-500/60 shadow-md'
                  : 'bg-slate-900 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between text-2xs mb-2">
                <span className="font-mono font-bold text-sky-400">{inc.id}</span>
                <span
                  className={`font-mono font-bold px-1.5 py-0.2 rounded text-[10px] ${
                    inc.severity === 'CRITICAL'
                      ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                      : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                  }`}
                >
                  Score: {inc.priorityScore}/100
                </span>
              </div>

              <h4 className="text-xs font-bold text-white mb-2 line-clamp-1">
                {inc.title}
              </h4>

              <p className="text-xs text-slate-300 line-clamp-3 leading-relaxed mb-3">
                {inc.bluf?.bottomLine}
              </p>

              <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-2xs text-slate-400">
                <span>{inc.sourcesCount} Corroborating Sources</span>
                <span className="font-mono text-emerald-400">{inc.confidence}% Conf</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
