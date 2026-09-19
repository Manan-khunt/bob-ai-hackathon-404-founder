import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Radio, ChevronRight, CheckCircle2, AlertCircle, Activity } from 'lucide-react';
import { useAppStore } from '../../store';

export default function IntelligenceSourcesPanel() {
  const navigate = useNavigate();
  const sources = useAppStore((s) => s.sources);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-sky-400" />
          <h3 className="text-xs font-bold text-white uppercase tracking-wider">
            INTELLIGENCE INGESTION TELEMETRY
          </h3>
        </div>
        <button
          onClick={() => navigate('/sources')}
          className="text-2xs font-semibold text-sky-400 hover:text-sky-300 flex items-center gap-1"
        >
          View Telemetry Matrix
          <ChevronRight className="w-3 h-3" />
        </button>
      </div>
      <p className="text-xs text-slate-400 mb-4">
        Real-time ingress status across external feeds, tactical sensors, and orbital downlinks.
      </p>

      {/* Grid of Sources */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {sources.slice(0, 4).map((src) => {
          const isHealthy = src.status === 'Healthy';
          return (
            <div
              key={src.id}
              className="bg-slate-950 border border-slate-800 rounded p-3 flex flex-col justify-between hover:border-slate-700 transition-colors"
            >
              <div>
                <div className="flex items-center justify-between text-2xs mb-1">
                  <span className="font-mono font-bold text-sky-400">{src.type}</span>
                  <span
                    className={`flex items-center gap-1 text-[10px] font-semibold ${
                      isHealthy ? 'text-emerald-400' : 'text-amber-400'
                    }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        isHealthy ? 'bg-emerald-400' : 'bg-amber-400'
                      }`}
                    />
                    {src.status}
                  </span>
                </div>
                <div className="text-xs font-bold text-white truncate">{src.name}</div>
              </div>

              <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-2xs">
                <span className="text-slate-400">Throughput:</span>
                <span className="font-mono font-semibold text-slate-200">
                  {src.eventsPerMin} ev/min
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
