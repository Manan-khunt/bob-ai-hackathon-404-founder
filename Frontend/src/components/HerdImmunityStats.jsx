import { useStore } from '../store';

const METRICS = [
  { key: 'nodes_total', label: 'ENDPOINTS PROTECTED', color: '#00FF41' },
  { key: 'total_threats_seen', label: 'THREATS DETECTED', color: '#FF2D2D' },
  { key: 'contained', label: 'THREATS CONTAINED', color: '#FFB300' },
  { key: 'antibodies_total', label: 'KNOWN FINGERPRINTS', color: '#00B4D8' },
  { key: 'deflection', label: 'NEW-ATTACK DEFLECTION', color: '#7C3AED' },
];

export default function HerdImmunityStats() {
  const immunity = useStore(s => s.immunity);
  const nodes = useStore(s => s.nodes);

  const contained = Object.values(nodes).filter(n => n.status === 'quarantined' || n.status === 'immune').length;
  const stats = {
    nodes_total: immunity.nodes_total ?? Object.keys(nodes).length,
    total_threats_seen: immunity.total_threats_seen ?? 0,
    contained,
    antibodies_total: immunity.antibodies_total ?? 0,
    deflection: immunity.immunity_pct != null ? `${immunity.immunity_pct}%` : '--',
  };

  return (
    <div className="hacker-panel p-4">
      <div className="hacker-title text-sm mb-1">&gt; HERD IMMUNITY // LEARNED PROTECTION</div>
      <div className="font-mono text-hacker-muted text-[10px] mb-3">
        one attack is analyzed once, then every endpoint is protected by the same learned fingerprint
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {METRICS.map(m => (
          <div key={m.key} className="bg-hacker-panel border border-hacker-border rounded-hard p-3 text-center">
            <div className="font-orbitron font-bold text-xl" style={{ color: m.color }}>{stats[m.key]}</div>
            <div className="font-mono text-[9px] text-hacker-muted uppercase tracking-wider mt-1">{m.label}</div>
          </div>
        ))}
      </div>
      <div className="font-mono text-hacker-muted text-[9px] mt-3">
        metrics reflect live simulation state only — no external performance claims
      </div>
    </div>
  );
}