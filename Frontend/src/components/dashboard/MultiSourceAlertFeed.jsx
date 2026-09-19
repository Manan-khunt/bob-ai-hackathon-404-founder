import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Search,
  Filter,
  Layers,
  ArrowUpDown,
  CheckCircle2,
  AlertOctagon,
  ShieldQuestion,
  Eye,
  Radio,
} from 'lucide-react';
import { useAppStore } from '../../store';

const SOURCE_COLORS = {
  SIEM: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  'CYBER SENSOR': 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  SATELLITE: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  INTELLIGENCE: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  ENDPOINT: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
  'NETWORK SENSOR': 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  HONEYPOT: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  OSINT: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
};

export default function MultiSourceAlertFeed({ limit = 8 }) {
  const alerts = useAppStore((s) => s.alerts);
  const selectAlert = useAppStore((s) => s.selectAlert);
  const selectFalsePositive = useAppStore((s) => s.selectFalsePositive);

  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [classFilter, setClassFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredAlerts = alerts.filter((alert) => {
    if (sourceFilter !== 'ALL' && alert.source !== sourceFilter) return false;
    if (classFilter !== 'ALL' && alert.classification !== classFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        alert.id.toLowerCase().includes(q) ||
        alert.asset.toLowerCase().includes(q) ||
        alert.event.toLowerCase().includes(q) ||
        alert.source.toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  const displayedAlerts = limit ? filteredAlerts.slice(0, limit) : filteredAlerts;

  return (
    <div className="bg-slate-900/95 border border-slate-800 rounded-lg overflow-hidden shadow-defence select-none">
      {/* Feed Header */}
      <div className="px-5 py-3.5 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 bg-slate-950/40">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xs font-bold text-white uppercase tracking-wider">
              MULTI-SOURCE ALERT FEED
            </h2>
            <span className="text-2xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-semibold font-mono flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              LIVE FUSION ({displayedAlerts.length})
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Heterogeneous telemetry normalized into standardized threat indicators.
          </p>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search alert, asset, IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-950 border border-slate-700 text-xs text-slate-200 pl-8 pr-3 py-1 rounded w-44 placeholder:text-slate-400 focus:outline-none focus:border-sky-500"
            />
          </div>

          {/* Source Filter */}
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-xs text-slate-300 px-2 py-1 rounded focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Sources (8)</option>
            <option value="SIEM">SIEM</option>
            <option value="CYBER SENSOR">Cyber Sensor</option>
            <option value="SATELLITE">Satellite</option>
            <option value="INTELLIGENCE">Intelligence</option>
            <option value="ENDPOINT">Endpoint</option>
            <option value="NETWORK SENSOR">Network Sensor</option>
            <option value="HONEYPOT">Honeypot</option>
            <option value="OSINT">OSINT</option>
          </select>

          {/* Classification Filter */}
          <select
            value={classFilter}
            onChange={(e) => setClassFilter(e.target.value)}
            className="bg-slate-950 border border-slate-700 text-xs text-slate-300 px-2 py-1 rounded focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Triage (All)</option>
            <option value="TRUE_THREAT">True Threats</option>
            <option value="FALSE_POSITIVE">False Positives (Suppressed)</option>
            <option value="NEEDS_REVIEW">Needs Review</option>
          </select>
        </div>
      </div>

      {/* Alert Feed Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950/70 text-2xs uppercase tracking-wider text-slate-400 border-b border-slate-800 select-none">
            <tr>
              <th className="py-2.5 px-4 font-semibold">Alert ID</th>
              <th className="py-2.5 px-3 font-semibold">Source</th>
              <th className="py-2.5 px-3 font-semibold">Time</th>
              <th className="py-2.5 px-3 font-semibold">Target Asset</th>
              <th className="py-2.5 px-4 font-semibold">Normalized Threat Event</th>
              <th className="py-2.5 px-3 font-semibold">Severity</th>
              <th className="py-2.5 px-3 font-semibold">Confidence</th>
              <th className="py-2.5 px-3 font-semibold">Correlation</th>
              <th className="py-2.5 px-3 font-semibold">Triage Disposition</th>
              <th className="py-2.5 px-4 font-semibold text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {displayedAlerts.length === 0 ? (
              <tr>
                <td colSpan={10} className="py-12 text-center text-slate-400">
                  <div className="flex flex-col items-center justify-center space-y-2">
                    <Filter className="w-8 h-8 text-slate-600" />
                    <div className="text-xs font-semibold text-slate-300">
                      No matching threat alerts found
                    </div>
                    <div className="text-2xs text-slate-500">
                      Try adjusting your search query, source filter, or triage classification.
                    </div>
                    <button
                      onClick={() => {
                        setSearchQuery('');
                        setSourceFilter('ALL');
                        setClassFilter('ALL');
                      }}
                      className="mt-2 px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-sky-400 text-2xs font-semibold transition-colors"
                    >
                      Reset All Filters
                    </button>
                  </div>
                </td>
              </tr>
            ) : (
              displayedAlerts.map((alert, idx) => {
              const isCrit = alert.severity === 'Critical';
              const isHigh = alert.severity === 'High';
              const isFP = alert.classification === 'FALSE_POSITIVE';
              const isTrueThreat = alert.classification === 'TRUE_THREAT';
              const sourceStyle =
                SOURCE_COLORS[alert.source] || 'bg-slate-800 text-slate-300 border-slate-700';

              return (
                <motion.tr
                  key={alert.id}
                  onClick={() => selectAlert(alert)}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2, delay: idx * 0.03 }}
                  whileHover={{ backgroundColor: 'rgba(30, 41, 59, 0.45)' }}
                  className="cursor-pointer transition-colors group"
                >
                  {/* ID */}
                  <td className="py-3 px-4 font-mono font-bold text-sky-400 text-xs group-hover:underline">
                    {alert.id}
                  </td>

                  {/* Source */}
                  <td className="py-3 px-3">
                    <span
                      className={`font-mono text-2xs font-semibold px-2 py-0.5 rounded border uppercase tracking-wider ${sourceStyle}`}
                    >
                      {alert.source}
                    </span>
                  </td>

                  {/* Time */}
                  <td className="py-3 px-3 font-mono text-slate-400 text-xs">
                    {alert.timestamp}
                  </td>

                  {/* Asset */}
                  <td className="py-3 px-3 font-medium text-slate-200">
                    <div>{alert.asset}</div>
                    <div className="text-[10px] font-mono text-slate-400">{alert.assetIp}</div>
                  </td>

                  {/* Event */}
                  <td className="py-3 px-4">
                    <div className="text-white font-medium text-xs line-clamp-1 group-hover:text-sky-200">
                      {alert.normalizedEvent}
                    </div>
                    <div className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                      {alert.event}
                    </div>
                  </td>

                  {/* Severity */}
                  <td className="py-3 px-3">
                    <span
                      className={`inline-flex items-center gap-1 text-2xs font-semibold px-1.5 py-0.5 rounded ${
                        isCrit
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : isHigh
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          : 'bg-slate-800 text-slate-300 border border-slate-700'
                      }`}
                    >
                      {isCrit && <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />}
                      {alert.severity}
                    </span>
                  </td>

                  {/* Confidence */}
                  <td className="py-3 px-3 font-mono font-semibold text-slate-200">
                    {alert.confidence}%
                  </td>

                  {/* Correlation */}
                  <td className="py-3 px-3">
                    <span
                      className={`font-mono text-2xs px-2 py-0.5 rounded font-semibold ${
                        alert.correlationStatus === 'CORRELATED'
                          ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30'
                          : alert.correlationStatus === 'EVALUATING'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          : 'bg-slate-800 text-slate-400 border border-slate-700'
                      }`}
                    >
                      {alert.correlationStatus}
                    </span>
                  </td>

                  {/* Triage */}
                  <td className="py-3 px-3">
                    {isTrueThreat ? (
                      <span className="inline-flex items-center gap-1 text-2xs font-bold text-rose-400">
                        <AlertOctagon className="w-3 h-3" />
                        TRUE THREAT
                      </span>
                    ) : isFP ? (
                      <div className="flex items-center gap-1.5">
                        <span className="inline-flex items-center gap-1 text-2xs font-bold text-emerald-400">
                          <CheckCircle2 className="w-3 h-3" />
                          FALSE POSITIVE
                        </span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            selectFalsePositive(alert);
                          }}
                          className="text-[10px] underline text-sky-400 hover:text-sky-300 font-semibold"
                          title="View Suppressed Evidence"
                        >
                          Evidence
                        </button>
                      </div>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-2xs font-bold text-amber-400">
                        <ShieldQuestion className="w-3 h-3" />
                        NEEDS REVIEW
                      </span>
                    )}
                  </td>

                  {/* Action */}
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        selectAlert(alert);
                      }}
                      className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-sky-400 transition-colors"
                      title="Inspect Alert Details"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                  </td>
                </motion.tr>
              );
            }))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
