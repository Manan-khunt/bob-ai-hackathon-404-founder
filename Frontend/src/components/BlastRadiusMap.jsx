import { useStore } from '../store';
import useApi from '../hooks/useApi';
import { NODE_DISPLAY } from '../lib/format';

export default function BlastRadiusMap() {
  const blast = useStore(s => s.blastRadius);
  const { quarantineNode } = useApi();

  if (!blast || !blast.propagation_chain?.length) return null;

  const chain = [
    { node_id: blast.infected_node, risk_level: 'infected', estimated_seconds_to_fall: null },
    ...blast.propagation_chain,
  ];

  const colorFor = (level, secs) => {
    if (level === 'infected') return '#FF2D2D';
    if (secs != null && secs < 15) return '#FF2D2D';
    if (secs != null && secs < 60) return '#FFB300';
    return '#00B4D8';
  };

  const atRisk = blast.propagation_chain.filter(e => e.risk_level !== 'medium');

  return (
    <div className="hacker-panel border-hacker-red p-4" style={{ borderColor: '#FF2D2D' }}>
      <div className="font-orbitron text-[13px] font-bold uppercase tracking-wider text-hacker-red mb-4">
        &gt; BLAST RADIUS // LATERAL MOVEMENT PREDICTION
      </div>

      <div className="flex items-end gap-0 overflow-x-auto pb-2">
        {chain.map((entry, i) => {
          const display = NODE_DISPLAY[entry.node_id] || { icon: '?', color: '#00FF41' };
          const color = colorFor(entry.risk_level, entry.estimated_seconds_to_fall);
          const secs = entry.estimated_seconds_to_fall;
          return (
            <div key={entry.node_id} className="flex items-end">
              {i > 0 && (
                <svg width="36" height="40" viewBox="0 0 36 40" className="shrink-0 -mb-1">
                  <line x1="0" y1="20" x2="36" y2="20" stroke="#1A2E1A" strokeWidth="1.5" strokeDasharray="5 4" className="animate-dash-flow" />
                </svg>
              )}
              <div className="flex flex-col items-center px-1 w-16">
                <div
                  className="w-6 h-6 rounded-full border-2 flex items-center justify-center font-orbitron text-[11px]"
                  style={{ borderColor: color, color, boxShadow: `0 0 8px ${color}55` }}
                >
                  {display.icon}
                </div>
                <div className="font-mono text-[10px] text-hacker-white mt-1.5 truncate w-full text-center">
                  {entry.node_id.replace('node-', '')}
                </div>
                <div className="font-mono text-[9px] mt-0.5" style={{ color }}>
                  {secs != null ? `fall ${secs}s` : 'infected'}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <button
        onClick={async () => {
          for (const e of atRisk) await quarantineNode(e.node_id);
        }}
        className="mt-4 px-4 py-2 border border-hacker-red bg-hacker-red/10 text-hacker-red rounded-hard text-[11px] uppercase tracking-wider hover:bg-hacker-red hover:text-hacker-black transition-all cursor-pointer"
      >
        [QUARANTINE ALL AT RISK]
      </button>
    </div>
  );
}