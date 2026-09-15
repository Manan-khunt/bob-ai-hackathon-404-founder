import { useState, useMemo } from 'react';
import { useStore } from '../store';
import { timeAgo, formatConf, confColor } from '../lib/format';
import { FaSyncAlt } from 'react-icons/fa';

const FILTERS = ['ALL', 'ACTIVE', 'EXPIRING', 'EXPIRED'];

export default function AntibodyLibrary() {
  const antibodies = useStore(s => s.antibodies);
  const [filter, setFilter] = useState('ALL');

  const normalized = useMemo(() => antibodies.map(ab => ({
    id: ab.antibody_id || ab.id,
    threatType: ab.threat_type || (ab.attackId || '').replace('_', '-'),
    status: (ab.decay_status || 'active').toLowerCase(),
    confidence: ab.effective_confidence != null ? ab.effective_confidence * 100 : (ab.effectiveConfidence || 1) * 100,
    created: ab.synthesized_at || ab.synthesizedAt || ab.created_at,
    halfLife: ab.half_life_hours || ab.halfLifeHours || 72,
    version: ab.version || 1,
    neutralized: ab.neutralized_count || ab.neutralizedCount || 0,
    mitre: ab.mitre,
  })), [antibodies]);

  const filtered = normalized.filter(ab => {
    if (filter === 'ALL') return true;
    if (filter === 'ACTIVE') return ab.status === 'active';
    if (filter === 'EXPIRING') return ab.status === 'expiring';
    return ab.status === 'expired';
  });

  const filterClass = (f) => f === filter
    ? 'bg-hacker-green text-hacker-black border-hacker-green'
    : 'bg-hacker-panel text-hacker-muted border-hacker-border hover:text-hacker-white';

  return (
    <div className="hacker-panel p-4">
      <div className="hacker-title text-sm mb-3">&gt; ANTIBODY WEB // IMMUNE MEMORY STORE</div>

      <div className="flex gap-2 mb-3">
        {FILTERS.map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`flex-1 text-center font-mono text-[10px] uppercase tracking-wider border rounded-hard py-1.5 cursor-pointer transition-colors ${filterClass(f)}`}
          >
            {f}
          </button>
        ))}
      </div>

      {!filtered.length ? (
        <div className="font-mono text-hacker-muted text-[11px]">no antibodies in store // immune memory empty</div>
      ) : (
        <div className="space-y-1">
          <div className="grid grid-cols-[1fr_100px_70px_70px_60px] gap-2 px-2 py-1 border-b border-hacker-border font-orbitron text-[10px] uppercase tracking-wider text-hacker-muted">
            <span>THREAT</span>
            <span>CONFIDENCE</span>
            <span>HALF-LIFE</span>
            <span>V</span>
            <span>BLOCKED</span>
          </div>
          {filtered.map(ab => (
            <div
              key={ab.id}
              className="grid grid-cols-[1fr_100px_70px_70px_60px] gap-2 items-center px-2 py-2 rounded-hard border border-hacker-border/60 hover:bg-hacker-border/30 transition-colors font-mono text-[11px]"
            >
              <div className="min-w-0">
                <div className="text-hacker-white truncate">{ab.threatType}</div>
                <div className="text-hacker-muted text-[9px] truncate">{ab.id}</div>
              </div>
              <div>
                <div className="conf-bar"><span className={confColor(ab.confidence)} style={{ width: `${Math.min(100, ab.confidence)}%` }} /></div>
                <div className={`text-[10px] mt-0.5 ${ab.confidence < 40 ? 'text-hacker-amber' : 'text-hacker-muted'}`}>
                  {ab.confidence < 40 ? (<span className="inline-flex items-center gap-1"><FaSyncAlt className="animate-spin w-2.5 h-2.5" /> re-vaccinating</span>) : formatConf(ab.confidence)}
                </div>
              </div>
              <span className="text-hacker-muted text-[10px]">{ab.halfLife}h</span>
              <span className="text-hacker-blue text-[10px]">v{ab.version}</span>
              <span className="text-hacker-green text-[10px]">{ab.neutralized}</span>
            </div>
          ))}
        </div>
      )}

      <div className="font-mono text-hacker-muted text-[9px] mt-3">
        {normalized.length} total // last synthesis {normalized.length ? timeAgo(normalized[0].created) : 'n/a'}
      </div>
    </div>
  );
}