import React from 'react';
import { Clock, CheckCircle2, ShieldAlert, Cpu, Radio } from 'lucide-react';
import { useAppStore } from '../../store';

export default function CommanderTimeline() {
  const selectedIncidentId = useAppStore((s) => s.selectedIncidentId);
  const incidents = useAppStore((s) => s.incidents);

  const incident =
    incidents.find((i) => i.id === selectedIncidentId) || incidents[0];
  const timeline = incident.timeline || [];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-sky-400" />
          <h3 className="text-xs font-bold text-white uppercase tracking-wider">
            CHRONOLOGICAL INCIDENT TIMELINE
          </h3>
        </div>
        <span className="text-2xs font-mono text-slate-400">
          Target: <strong className="text-sky-400">{incident.id}</strong>
        </span>
      </div>
      <p className="text-xs text-slate-400 mb-4">
        Multi-source progression from initial detection to decision-grade commander BLUF.
      </p>

      {/* Timeline List */}
      <div className="relative pl-6 space-y-4 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
        {timeline.map((item, idx) => {
          const isAIEscalation = item.source.includes('IMMUNE-NET');
          return (
            <div key={idx} className="relative group">
              {/* Dot */}
              <span
                className={`absolute -left-6 top-1 w-2.5 h-2.5 rounded-full border-2 border-slate-950 transition-colors ${
                  isAIEscalation
                    ? 'bg-sky-400 shadow-sm shadow-sky-400/50'
                    : 'bg-slate-500'
                }`}
              />

              <div className="bg-slate-950/60 border border-slate-800/80 rounded p-2.5 hover:border-slate-700 transition-colors">
                <div className="flex items-center justify-between text-2xs mb-1">
                  <span className="font-mono font-bold text-sky-400">{item.time}</span>
                  <span
                    className={`font-mono text-[10px] px-1.5 py-0.2 rounded font-semibold ${
                      isAIEscalation
                        ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {item.source}
                  </span>
                </div>
                <div className="text-xs text-slate-200 font-medium">
                  {item.event}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
