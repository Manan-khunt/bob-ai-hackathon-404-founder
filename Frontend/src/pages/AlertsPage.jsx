import React from 'react';
import MultiSourceAlertFeed from '../components/dashboard/MultiSourceAlertFeed';
import { BellRing, ShieldCheck, Database, Filter } from 'lucide-react';
import { useAppStore } from '../store';

export default function AlertsPage() {
  const alerts = useAppStore((s) => s.alerts);
  const total = alerts.length;
  const trueThreats = alerts.filter((a) => a.classification === 'TRUE_THREAT').length;
  const falsePositives = alerts.filter((a) => a.classification === 'FALSE_POSITIVE').length;
  const needsReview = alerts.filter((a) => a.classification === 'NEEDS_REVIEW').length;

  return (
    <div className="space-y-6 max-w-[1700px] mx-auto pb-12">
      {/* Overview Stat Ribbon */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5">
          <div className="text-2xs font-bold text-slate-400 uppercase">Total Ingested Alerts</div>
          <div className="text-2xl font-extrabold text-white font-mono mt-1">1,284</div>
          <div className="text-[11px] text-slate-400 mt-0.5">8 Ingestion Streams Active</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5">
          <div className="text-2xs font-bold text-rose-400 uppercase">Confirmed True Threats</div>
          <div className="text-2xl font-extrabold text-rose-400 font-mono mt-1">{trueThreats}</div>
          <div className="text-[11px] text-slate-400 mt-0.5">Corroborated by ≥ 2 Sensors</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5">
          <div className="text-2xs font-bold text-emerald-400 uppercase">Auto-Suppressed Noise</div>
          <div className="text-2xl font-extrabold text-emerald-400 font-mono mt-1">1,147</div>
          <div className="text-[11px] text-slate-400 mt-0.5">91.4% False Positive Reduction</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5">
          <div className="text-2xs font-bold text-amber-400 uppercase">Pending Triage</div>
          <div className="text-2xl font-extrabold text-amber-400 font-mono mt-1">{needsReview}</div>
          <div className="text-[11px] text-slate-400 mt-0.5">Awaiting Host Telemetry</div>
        </div>
      </div>

      {/* Full Alert Feed */}
      <MultiSourceAlertFeed limit={0} />
    </div>
  );
}
