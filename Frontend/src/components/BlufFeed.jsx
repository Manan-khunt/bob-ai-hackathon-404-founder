import { useState } from 'react';
import { useStore } from '../store';
import { shortTime, formatConf } from '../lib/format';

function severityInfo(sev) {
  const s = String(sev || 'info').toUpperCase();
  if (s.includes('CRIT') || s.includes('CRITICAL')) return { border: '#FF2D2D', badge: 'CRITICAL', color: '#FF2D2D' };
  if (s === 'ALERT' || s.includes('WARN')) return { border: '#FFB300', badge: 'ALERT', color: '#FFB300' };
  if (s === 'SUCCESS') return { border: '#00FF41', badge: 'SUCCESS', color: '#00FF41' };
  return { border: '#3D6B3D', badge: 'INFO', color: '#3D6B3D' };
}

export default function BlufFeed({ limit = 10 }) {
  const incidents = useStore(s => s.incidents);
  const [open, setOpen] = useState(null);

  if (!incidents.length) {
    return (
      <div className="hacker-panel p-4">
        <div className="hacker-title text-sm mb-2">&gt; INTEL FEED // BLUF BRIEFINGS</div>
        <div className="font-mono text-hacker-muted text-[11px]">no briefings on record // mesh awaiting first engagement</div>
      </div>
    );
  }

  return (
    <div className="hacker-panel p-4">
      <div className="hacker-title text-sm mb-3">&gt; INTEL FEED // BLUF BRIEFINGS</div>
      <div className="space-y-2">
        {incidents.slice(0, limit).map(inc => {
          const sev = severityInfo(inc.confidence > 0.95 ? 'critical' : 'alert');
          const expanded = open === inc.incident_id;
          const apt = inc.threat_actor_attributions?.[0];
          return (
            <div key={inc.incident_id} className="bg-hacker-panel rounded-hard p-3" style={{ borderLeft: `3px solid ${sev.border}` }}>
              <div className="flex items-center gap-2 font-mono text-[11px]">
                <span className="node-badge" style={{ backgroundColor: `${sev.color}22`, color: sev.color }}>{sev.badge}</span>
                <span className="text-hacker-muted">{shortTime(inc.timestamp)}</span>
                <span className="text-hacker-white">{inc.node_id}</span>
              </div>
              <div className="flex flex-wrap gap-1 mt-2">
                <span className="tech-pill">{inc.mitre?.technique_id || 'T???'}</span>
                <span className="tech-pill">{inc.scenario || inc.attack_type}</span>
              </div>
              {apt && apt.confidence_pct > 0 && (
                <div className="font-mono text-[11px] text-hacker-red mt-1.5">
                  &gt; ATTRIBUTED: {apt.name} ({Math.round(apt.confidence_pct)}%)
                </div>
              )}
              <button
                className="text-left block w-full mt-1 font-body text-hacker-white text-[13px] leading-5 hover:text-hacker-green-dim transition-colors cursor-pointer"
                onClick={() => setOpen(expanded ? null : inc.incident_id)}
              >
                {inc.bluf_summary ? inc.bluf_summary.split('\n')[0] : `${inc.scenario || inc.attack_type} confirmed on ${inc.node_id}`}
              </button>
              <div className="mt-2 flex justify-end">
                <button
                  onClick={() => setOpen(expanded ? null : inc.incident_id)}
                  className="font-mono text-[10px] uppercase tracking-wider text-hacker-muted hover:text-hacker-green transition-colors cursor-pointer"
                >
                  [ACKNOWLEDGE]
                </button>
              </div>
              {expanded && (
                <pre className="mt-2 p-3 bg-hacker-black border border-hacker-border rounded-hard font-mono text-hacker-green text-[11px] leading-5 whitespace-pre-wrap">
                  {inc.bluf_summary || 'No BLUF block generated.'}
                </pre>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}