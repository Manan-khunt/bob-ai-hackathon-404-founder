import { useEffect } from 'react';
import { useStore } from '../store';
import useApi from '../hooks/useApi';
import { NODE_DISPLAY } from '../lib/format';

export default function NodeDetailPanel() {
  const selectedNodeId = useStore(s => s.selectedNodeId);
  const selectNode = useStore(s => s.selectNode);
  const node = useStore(s => s.nodes[selectedNodeId]);
  const { quarantineNode, releaseNode } = useApi();

  const close = () => selectNode(null);

  if (!selectedNodeId) return null;

  const n = node || { agent_id: selectedNodeId, status: 'healthy', anomaly_score: 4.0, biomarkers: {}, antibodies_installed: [], ip: '', owner_id: 'admin_1' };
  const bm = n.biomarkers || {};
  const b = NODE_DISPLAY[selectedNodeId] || { icon: '?', color: '#00FF41' };
  const isDecoy = selectedNodeId === 'node-decoy';

  return (
    <>
      {/* backdrop */}
      <div className="fixed inset-0 bg-black/50 z-40" onClick={close} />
      {/* panel */}
      <div className="fixed top-0 right-0 h-full w-[340px] bg-hacker-black border-l border-hacker-green z-50 overflow-y-auto animate-fade-in font-mono text-sm">
        {/* header */}
        <div className="flex items-center justify-between p-4 border-b border-hacker-border">
          <span className="hacker-title text-sm">&gt; NODE DETAIL // {selectedNodeId}</span>
          <button onClick={close} className="text-hacker-muted hover:text-hacker-white text-lg font-bold cursor-pointer">X</button>
        </div>

        <div className="p-4 space-y-6">
          {/* TELEM */}
          <div>
            <div className="label-muted mb-1">&gt; TELEMETRY</div>
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div className="bg-hacker-panel rounded-hard border border-hacker-border p-2">
                <div className="label-muted">CPU</div>
                <div className="font-orbitron text-hacker-green text-lg mt-0.5">{bm.cpu != null ? `${Number(bm.cpu).toFixed(0)}%` : '--'}</div>
              </div>
              <div className="bg-hacker-panel rounded-hard border border-hacker-border p-2">
                <div className="label-muted">MEMORY</div>
                <div className="font-orbitron text-hacker-green text-lg mt-0.5">{bm.memory != null ? `${Number(bm.memory).toFixed(0)}%` : '--'}</div>
              </div>
              <div className="bg-hacker-panel rounded-hard border border-hacker-border p-2">
                <div className="label-muted">ENTROPY</div>
                <div className="font-orbitron text-hacker-green text-lg mt-0.5">{bm.entropy != null ? Number(bm.entropy).toFixed(2) : '--'}</div>
              </div>
              <div className="bg-hacker-panel rounded-hard border border-hacker-border p-2">
                <div className="label-muted">SOCKET</div>
                <div className="font-orbitron text-hacker-green text-lg mt-0.5">{bm.socketLoad != null ? bm.socketLoad : '--'}</div>
              </div>
            </div>
            <div className="text-hacker-muted text-[10px] mt-1">IP: {n.ip || '--'}</div>
          </div>

          {/* ANOMALY */}
          <div>
            <div className="label-muted mb-1">&gt; ANOMALY SCORE</div>
            <div className="font-orbitron text-3xl text-hacker-green">{n.anomaly_score != null ? n.anomaly_score.toFixed(1) : '4.0'}</div>
            <div className={`text-[11px] uppercase ${n.status === 'quarantined' ? 'text-hacker-amber' : n.status === 'infected' ? 'text-hacker-red' : 'text-hacker-green'}`}>
              {n.status?.toUpperCase() || 'HEALTHY'}
            </div>
          </div>

          {/* ANTIBODIES */}
          <div>
            <div className="label-muted mb-1">&gt; ANTIBODIES</div>
            {n.antibodies_installed?.length > 0 ? (
              <div className="space-y-1">
                {n.antibodies_installed.map((ab, i) => (
                  <div key={i} className="bg-hacker-panel rounded-hard border border-hacker-border p-1.5 text-[10px] font-mono text-hacker-green truncate">{ab}</div>
                ))}
              </div>
            ) : (
              <div className="text-hacker-muted text-[11px]">No antibodies installed</div>
            )}
          </div>

          {/* ACTIONS */}
          <div>
            <div className="label-muted mb-2">&gt; ACTIONS</div>
            <div className="flex flex-col gap-2">
              {!isDecoy && (
                <>
                  <button
                    onClick={() => quarantineNode(selectedNodeId)}
                    className="w-full py-2 px-3 border border-hacker-red bg-hacker-red/10 text-hacker-red rounded-hard text-[11px] uppercase tracking-wider hover:bg-hacker-red hover:text-hacker-black transition-all cursor-pointer"
                  >
                    QUARANTINE
                  </button>
                  <button
                    onClick={() => releaseNode(selectedNodeId)}
                    className="w-full py-2 px-3 border border-hacker-green bg-hacker-green/10 text-hacker-green rounded-hard text-[11px] uppercase tracking-wider hover:bg-hacker-green hover:text-hacker-black transition-all cursor-pointer"
                  >
                    RELEASE
                  </button>
                </>
              )}
              <button
                onClick={() => { selectNode(selectedNodeId); }}
                className="w-full py-2 px-3 border border-hacker-blue bg-hacker-blue/10 text-hacker-blue rounded-hard text-[11px] uppercase tracking-wider hover:bg-hacker-blue hover:text-hacker-black transition-all cursor-pointer"
              >
                SCAN NOW
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}