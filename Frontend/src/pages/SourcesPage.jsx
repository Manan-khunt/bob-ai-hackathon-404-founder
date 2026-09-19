import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Radio, Activity, CheckCircle2, AlertTriangle, ShieldCheck, Search, Filter } from 'lucide-react';
import { useAppStore } from '../store';
import AnimatedCounter from '../components/common/AnimatedCounter';

export default function SourcesPage() {
  const sources = useAppStore((s) => s.sources);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');

  const filtered = sources.filter((src) => {
    if (statusFilter !== 'ALL' && src.status !== statusFilter) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        src.name.toLowerCase().includes(q) ||
        src.type.toLowerCase().includes(q) ||
        src.coverage.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6 max-w-[1700px] mx-auto pb-12 select-none">
      {/* Header with Search & Filter */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Radio className="w-5 h-5 text-sky-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              MULTI-SOURCE INGESTION &amp; SENSOR HEALTH MATRIX
            </h2>
            <span className="text-2xs font-mono px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 border border-sky-500/30">
              8 ACTIVE FEEDS
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Continuous telemetry ingestion monitoring across satellite constellations, tactical sensor meshes, and allied intelligence exchanges.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search sources, type, coverage..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-slate-950 border border-slate-700 text-xs text-slate-200 pl-8 pr-3 py-1.5 rounded w-52 placeholder:text-slate-400 focus:outline-none focus:border-sky-500"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-xs text-slate-300 px-2.5 py-1.5 rounded focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Health</option>
            <option value="Healthy">Healthy (7)</option>
            <option value="Degraded">Degraded (1)</option>
          </select>
        </div>
      </div>

      {/* Sources Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {filtered.map((src, idx) => {
          const isHealthy = src.status === 'Healthy';
          return (
            <motion.div
              key={src.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.25, delay: idx * 0.04 }}
              whileHover={{ y: -2, scale: 1.01 }}
              className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col justify-between hover:border-slate-700 transition-all shadow-defence"
            >
              <div>
                <div className="flex items-center justify-between text-2xs mb-2">
                  <span className="font-mono font-bold text-sky-400 text-xs">{src.type}</span>
                  <span
                    className={`flex items-center gap-1.5 text-2xs font-semibold px-2 py-0.5 rounded ${
                      isHealthy
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    }`}
                  >
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        isHealthy ? 'bg-emerald-400' : 'bg-amber-400 animate-pulse'
                      }`}
                    />
                    {src.status}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-white mb-1">{src.name}</h3>
                <p className="text-xs text-slate-400 leading-relaxed mb-3">
                  {src.description}
                </p>

                <div className="bg-slate-950 border border-slate-800/80 rounded p-2.5 text-xs space-y-1.5 font-mono">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Throughput:</span>
                    <span className="text-white font-semibold">
                      <AnimatedCounter value={src.eventsPerMin} suffix=" ev/min" />
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Latency:</span>
                    <span className="text-sky-300">{src.latencyMs} ms</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">Last Sync:</span>
                    <span className="text-slate-300">{src.lastUpdate}</span>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-2.5 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
                <span>Coverage:</span>
                <span className="text-slate-300 font-medium truncate max-w-[150px]">{src.coverage}</span>
              </div>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
