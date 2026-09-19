import React from 'react';
import { motion } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { Shield, ChevronRight, AlertTriangle, ArrowUpRight, Lock } from 'lucide-react';
import { useAppStore } from '../../store';
import AnimatedCounter from '../common/AnimatedCounter';

export default function PrioritizedThreatsTable() {
  const navigate = useNavigate();
  const incidents = useAppStore((s) => s.incidents);
  const selectedIncidentId = useAppStore((s) => s.selectedIncidentId);
  const selectIncident = useAppStore((s) => s.selectIncident);

  const handleRowClick = (id) => {
    selectIncident(id);
    navigate('/incidents');
  };

  return (
    <div className="bg-slate-900/95 border border-slate-800 rounded-lg overflow-hidden shadow-defence">
      {/* Header Bar */}
      <div className="px-5 py-3.5 border-b border-slate-800 flex items-center justify-between bg-slate-950/40 select-none">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider">
              PRIORITIZED THREATS
            </h2>
            <span className="text-2xs px-2 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/30 font-semibold font-mono">
              RANKED BY THREAT SCORE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Top correlated incidents ranked by dynamic multi-variable impact equation.
          </p>
        </div>

        <button
          onClick={() => navigate('/incidents')}
          className="text-2xs font-semibold text-sky-400 hover:text-sky-300 flex items-center gap-1 transition-colors px-2.5 py-1 rounded bg-slate-800/80 hover:bg-slate-800 border border-slate-700"
        >
          View Full Incident Queue
          <ChevronRight className="w-3 h-3" />
        </button>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950/70 text-2xs uppercase tracking-wider text-slate-400 border-b border-slate-800 select-none">
            <tr>
              <th className="py-2.5 px-4 font-semibold w-12 text-center">Rank</th>
              <th className="py-2.5 px-4 font-semibold">Incident / Threat Vector</th>
              <th className="py-2.5 px-3 font-semibold">Assets</th>
              <th className="py-2.5 px-3 font-semibold">Sources</th>
              <th className="py-2.5 px-3 font-semibold">Confidence</th>
              <th className="py-2.5 px-3 font-semibold">MITRE ATT&CK</th>
              <th className="py-2.5 px-3 font-semibold">Severity</th>
              <th className="py-2.5 px-4 font-semibold text-right">Priority Score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {incidents.slice(0, 5).map((inc, idx) => {
              const isSelected = selectedIncidentId === inc.id;
              const isCritical = inc.severity === 'CRITICAL';
              const isHigh = inc.severity === 'HIGH';
              const isFP = inc.classification === 'FALSE_POSITIVE';

              return (
                <motion.tr
                  key={inc.id}
                  onClick={() => handleRowClick(inc.id)}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.25, delay: idx * 0.05 }}
                  whileHover={{ backgroundColor: 'rgba(30, 41, 59, 0.45)' }}
                  className={`cursor-pointer transition-colors group relative ${
                    isSelected ? 'bg-sky-500/10' : ''
                  }`}
                >
                  {/* Rank */}
                  <td className="py-3 px-4 text-center font-mono font-bold text-slate-400 text-xs">
                    <span className="group-hover:text-sky-400 transition-colors">
                      {inc.priorityRank}
                    </span>
                  </td>

                  {/* Incident details */}
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-sky-400 text-xs group-hover:underline flex items-center gap-1">
                        {inc.id}
                        <ArrowUpRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                      </span>
                      {isCritical && (
                        <span className="text-[10px] px-1.5 py-0.2 rounded font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1">
                          <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
                          CRITICAL
                        </span>
                      )}
                      {isFP && (
                        <span className="text-[10px] px-1.5 py-0.2 rounded font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                          AUTO-SUPPRESSED
                        </span>
                      )}
                    </div>
                    <div className="text-xs font-semibold text-white mt-0.5 line-clamp-1 group-hover:text-sky-100">
                      {inc.title}
                    </div>
                    <div className="text-[11px] text-slate-400 truncate mt-0.5">
                      {inc.threatType} • Attribution: <strong className="text-slate-300">{inc.attribution}</strong>
                    </div>
                  </td>

                  {/* Assets */}
                  <td className="py-3 px-3">
                    <span className="font-semibold text-slate-200">
                      {inc.assetsCount} {inc.assetsCount === 1 ? 'asset' : 'assets'}
                    </span>
                    <div className="text-[10px] text-slate-400 truncate max-w-[120px]">
                      {inc.affectedAssets?.map((a) => a.id).join(', ')}
                    </div>
                  </td>

                  {/* Sources */}
                  <td className="py-3 px-3">
                    <div className="flex flex-wrap gap-1 max-w-[150px]">
                      {inc.sources?.map((s) => (
                        <span
                          key={s}
                          className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700/80"
                        >
                          {s}
                        </span>
                      ))}
                    </div>
                  </td>

                  {/* Confidence */}
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold text-slate-200 text-xs w-8">
                        <AnimatedCounter value={inc.confidence} suffix="%" duration={600} />
                      </span>
                      <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${inc.confidence}%` }}
                          transition={{ duration: 0.8, ease: 'easeOut' }}
                          className={`h-full rounded-full ${
                            inc.confidence >= 90
                              ? 'bg-emerald-400'
                              : inc.confidence >= 70
                              ? 'bg-sky-400'
                              : 'bg-amber-400'
                          }`}
                        />
                      </div>
                    </div>
                  </td>

                  {/* MITRE */}
                  <td className="py-3 px-3">
                    <span className="font-mono text-2xs px-1.5 py-0.5 rounded bg-sky-950/80 text-sky-300 border border-sky-800/80 font-semibold">
                      {inc.mitreId}
                    </span>
                    <div className="text-[10px] text-slate-400 truncate max-w-[110px] mt-0.5">
                      {inc.mitreTechnique}
                    </div>
                  </td>

                  {/* Status / Severity */}
                  <td className="py-3 px-3">
                    <span
                      className={`inline-flex items-center gap-1 text-2xs font-semibold px-2 py-0.5 rounded ${
                        isCritical
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                          : isHigh
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          : 'bg-slate-800 text-slate-300 border border-slate-700'
                      }`}
                    >
                      {isCritical && <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />}
                      {inc.severity}
                    </span>
                  </td>

                  {/* Priority Score */}
                  <td className="py-3 px-4 text-right">
                    <div className="inline-flex flex-col items-end">
                      <span
                        className={`text-base font-extrabold font-mono leading-none ${
                          inc.priorityScore >= 90
                            ? 'text-rose-400'
                            : inc.priorityScore >= 70
                            ? 'text-amber-400'
                            : 'text-slate-400'
                        }`}
                      >
                        <AnimatedCounter value={inc.priorityScore} duration={800} />
                      </span>
                      <span className="text-[9px] text-slate-500 uppercase font-mono mt-0.5">
                        / 100
                      </span>
                    </div>
                  </td>
                </motion.tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
