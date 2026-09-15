import { useEffect, useState } from 'react';
import { useStore } from '../store';
import { shortTime } from '../lib/format';

const ROWS_KEY = 'hp-flash';

export default function HoneypotLog() {
  const events = useStore(s => s.honeypotEvents);
  const [newIds, setNewIds] = useState([]);

  useEffect(() => {
    const known = JSON.parse(localStorage.getItem(ROWS_KEY) || '[]');
    const fresh = events.filter(e => !known.includes(e.event_id));
    if (fresh.length) {
      const ids = fresh.map(e => e.event_id);
      setNewIds(ids);
      localStorage.setItem(ROWS_KEY, JSON.stringify([...known, ...ids].slice(-50)));
      setTimeout(() => setNewIds([]), 400);
    }
  }, [events]);

  return (
    <div className="hacker-panel p-4" style={{ borderColor: '#3B0764' }}>
      <div className="font-orbitron text-sm font-bold uppercase tracking-wider text-hacker-purple mb-3">
        &gt; HONEYPOT // DECOY NODE INTEL
      </div>

      {!events.length ? (
        <div className="font-mono text-hacker-muted text-[11px]">
          &gt; no attacks captured // node-decoy is listening...<span className="cursor" />
        </div>
      ) : (
        <div className="space-y-1">
          <div className="grid grid-cols-[90px_140px_100px_1fr_130px] gap-2 px-2 py-1 border-b border-hacker-purple/30 font-orbitron text-[10px] uppercase tracking-wider text-hacker-muted">
            <span>TIME</span>
            <span>SOURCE</span>
            <span>VECTOR</span>
            <span>ANTIBODY</span>
            <span>STATUS</span>
          </div>
          {events.slice(0, 20).map(e => (
            <div
              key={e.event_id}
              className={`grid grid-cols-[90px_140px_100px_1fr_130px] gap-2 items-center px-2 py-1.5 rounded-hard border border-transparent font-mono text-[11px] ${
                newIds.includes(e.event_id) ? 'animate-flash-green bg-hacker-green/30' : ''
              }`}
              style={newIds.includes(e.event_id) ? { backgroundColor: 'rgba(0,255,65,0.25)' } : undefined}
            >
              <span className="text-hacker-muted text-[10px]">{shortTime(e.timestamp)}</span>
              <span className="text-hacker-white truncate">{e.source_ip}</span>
              <span className="text-hacker-green">{e.attack_vector}</span>
              <span className="text-hacker-blue text-[10px] truncate">{e.antibody_id || 'n/a'}</span>
              <span className="node-badge bg-hacker-green/20 text-hacker-green justify-self-start">
                {e.status === 'captured' ? 'CAPTURED' : 'ANTIBODY_TRIGGERED'}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}