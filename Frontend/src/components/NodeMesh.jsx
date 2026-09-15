import { useStore } from '../store';
import { NODE_DISPLAY, NODE_GRID, timeAgo } from '../lib/format';
import NodeDetailPanel from './NodeDetailPanel';

function statusOf(node) {
  const st = (node.status || 'healthy').toLowerCase();
  if (node.agent_id === 'node-decoy') return 'honeypot';
  if (st === 'quarantined') return 'quarantine';
  if (st === 'infected') return 'infected';
  return 'immune';
}

export default function NodeMesh() {
  const nodes = useStore(s => s.nodes);
  const selectNode = useStore(s => s.selectNode);
  const decoyEvents = useStore(s => s.honeypotEvents.length);

  const fleetEntries = Object.entries(nodes).filter(([id]) => id !== 'node-decoy');
  const activeCount = fleetEntries.filter(([, n]) => n.status === 'healthy' || n.status === 'immune').length;

  const badgeFor = (status) => {
    switch (status) {
      case 'infected': return { text: 'BREACH', cls: 'bg-hacker-red/20 text-hacker-red' };
      case 'quarantine': return { text: 'ISOLATED', cls: 'bg-hacker-amber/20 text-hacker-amber' };
      case 'honeypot': return { text: 'DECOY', cls: 'bg-hacker-purple/20 text-hacker-purple' };
      default: return { text: 'ARMED', cls: 'bg-hacker-green/20 text-hacker-green' };
    }
  };

  const nodeCardStyle = (status) => {
    switch (status) {
      case 'infected':
        return 'border-hacker-red bg-hacker-red/5 animate-pulse-red';
      case 'quarantine':
        return 'border-hacker-amber bg-hacker-amber/5';
      case 'honeypot':
        return 'border-hacker-purple bg-hacker-purple/5';
      default:
        return 'border-hacker-green bg-hacker-panel';
    }
  };

  return (
    <div className="hacker-panel p-4">
      <div className="hacker-title text-sm mb-3">
        &gt; NODE SWARM MESH // {activeCount} ACTIVE
      </div>

      <div className="relative">
        <svg className="absolute inset-0 w-full h-full pointer-events-none" style={{ zIndex: 0 }}>
          {NODE_GRID.slice(0, 3).flatMap((row, r) =>
            row.slice(0, 3).map((id, c) => {
              if (c === row.length - 1) return null;
              const a = id;
              const b = row[c + 1];
              const x1 = `${(c + 0.5) * 33.33}%`;
              const y1 = `${(r + 0.5) * 33.33}%`;
              const x2 = `${(c + 1.5) * 33.33}%`;
              const y2 = `${(r + 0.5) * 33.33}%`;
              return (
                <line
                  key={`${a}-${b}-h`}
                  x1={x1} y1={y1} x2={x2} y2={y2}
                  stroke="rgba(0,255,65,0.2)"
                  strokeWidth="1"
                  strokeDasharray="4 4"
                  className="animate-dash-flow"
                />
              );
            })
          )}
          {NODE_GRID.slice(0, 3).map((row, r) =>
            r === 0 ? null : row.slice(0, 3).map((id, c) => {
              const above1 = NODE_GRID[r - 1][c];
              const above2 = NODE_GRID[r - 1][c + 1];
              const lines = [];
              if (above1) lines.push([above1, id, -1]);
              if (above2 && above2 !== 'node-decoy') lines.push([above2, id, 1]);
              return lines.map(([a, b, side]) => (
                <line
                  key={`${a}-${b}-${side}`}
                  x1={`${(c + 0.5 + side * 0.07) * 33.33}%`} y1={`${(r - 0.5) * 33.33}%`}
                  x2={`${(c + 0.57 + side * 0.07) * 33.33}%`} y2={`${(r - 0.5) * 33.33}%`}
                  stroke="rgba(0,255,65,0.14)"
                  strokeWidth="1"
                  strokeDasharray="4 4"
                  className="animate-dash-flow"
                />
              ));
            })
          )}
        </svg>

        <div className="grid grid-cols-3 gap-3 relative z-10">
          {NODE_GRID.slice(0, 3).map((row, r) =>
            row.map((id, c) => {
              const node = nodes[id] || { agent_id: id };
              const status = statusOf(node);
              const badge = badgeFor(status);
              const display = NODE_DISPLAY[id] || { icon: id[5] || '?', color: '#00FF41' };
              const cpu = (node.biomarkers && node.biomarkers.cpu) != null
                ? Number(node.biomarkers.cpu) : 20;
              return (
                <button
                  key={id}
                  onClick={() => selectNode(id)}
                  className={`text-left border rounded-hard p-2.5 transition-all duration-200 hover:brightness-125 ${nodeCardStyle(status)}`}
                >
                  <div className="flex items-start justify-between gap-1">
                    <span className="font-orbitron font-bold text-[11px] uppercase truncate" style={{ color: status === 'honeypot' ? '#7C3AED' : status === 'infected' ? '#FF2D2D' : '#00FF41' }}>
                      {id.replace('node-', '')}
                    </span>
                    <span className={`node-badge ${badge.cls}`}>{badge.text}</span>
                  </div>
                  <div className="mt-2">
                    <div className="h-[3px] rounded-full bg-hacker-border overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${Math.min(100, Math.max(2, cpu))}%`, backgroundColor: status === 'honeypot' ? '#7C3AED' : '#00FF41' }} />
                    </div>
                  </div>
                  <div className="mt-1.5 flex items-center justify-between">
                    <span className="font-mono text-hacker-muted text-[10px]">ANO {node.anomaly_score != null ? node.anomaly_score.toFixed(1) : '4.0'}</span>
                    <span className="font-mono text-hacker-muted text-[10px]">{timeAgo(node.last_seen)}</span>
                  </div>
                </button>
              );
            })
          )}
        </div>
      </div>

      <div className="mt-4 border border-hacker-purple/40 bg-hacker-purple/5 rounded-hard p-2.5 flex items-center justify-between">
        <span className="font-orbitron text-[11px] uppercase tracking-wider text-hacker-purple">
          HONEYPOT DECOY // {decoyEvents} captured
        </span>
        <span className="node-badge bg-hacker-purple/20 text-hacker-purple">DECOY</span>
      </div>

      <NodeDetailPanel />
    </div>
  );
}