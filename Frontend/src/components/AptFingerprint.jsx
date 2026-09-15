import { useEffect, useState } from 'react';
import { useStore } from '../store';
import useApi from '../hooks/useApi';

export default function AptFingerprint() {
  const apt = useStore(s => s.aptAttribution);
  const incidents = useStore(s => s.incidents);
  const { fetchAptAttribution } = useApi();
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!incidents.length) return;
    const latest = incidents[0];
    if (apt && apt.incident_id === latest.incident_id) return;
    const run = async () => {
      if (loading) return;
      setLoading(true);
      await fetchAptAttribution(latest.incident_id);
      setLoading(false);
    };
    run();
  }, [incidents, apt, fetchAptAttribution, loading]);

  const rows = apt?.attribution || [];
  if (!rows.length) {
    return (
      <div className="hacker-panel p-4">
        <div className="hacker-title text-sm mb-2">&gt; THREAT ACTOR // APT ATTRIBUTION ENGINE</div>
        <div className="font-mono text-hacker-muted text-[11px]">waiting for confirmed incident to profile...</div>
      </div>
    );
  }

  return (
    <div className="hacker-panel p-4">
      <div className="hacker-title text-sm mb-1">&gt; THREAT ACTOR // APT ATTRIBUTION ENGINE</div>
      {apt && <div className="font-mono text-hacker-muted text-[10px] mb-3">incident: {apt.incident_id}</div>}
      <div className="space-y-3">
        {rows.map((r, i) => {
          const top = i === 0;
          const pct = Number(r.confidence_pct || 0);
          return (
            <div
              key={r.name}
              className={`rounded-hard p-3 ${
                top
                  ? 'border-2 border-hacker-red bg-hacker-red/5'
                  : 'border border-hacker-border bg-hacker-panel'
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-orbitron font-bold text-[13px] text-hacker-green">{r.name}</span>
                <span className="font-mono text-hacker-muted text-[10px]">{formatPct(pct)}</span>
              </div>
              <div className="flex flex-wrap gap-1 mt-2">
                {(r.matched_techniques || []).map(t => (
                  <span key={t} className="tech-pill">{t}</span>
                ))}
              </div>
              <div className="h-1.5 rounded-full bg-hacker-border overflow-hidden mt-2">
                <div className="h-full rounded-full bg-hacker-red" style={{ width: `${Math.min(100, pct)}%` }} />
              </div>
              {r.description && <div className="font-mono text-hacker-white/60 text-[10px] mt-2 leading-4">{r.description}</div>}
            </div>
          );
        })}
      </div>
      {apt?.top_match?.confidence_pct > 0 && (
        <div className="font-orbitron text-hacker-amber text-[11px] uppercase tracking-wider mt-3">
          &gt; RECOMMENDED: ESCALATE TO CISO
        </div>
      )}
    </div>
  );
}

function formatPct(v) {
  return v > 1 ? `${Math.round(v)}%` : `${Math.round(v * 100)}%`;
}