import { useState, useRef, useEffect } from 'react';
import useApi from '../hooks/useApi';

const QUICK = [
  { label: 'scan fleet', method: 'get_fleet_status' },
  { label: 'active threats', method: 'get_active_incidents' },
  { label: 'run simulation', method: 'run_simulation', params: { scenario: 'cryptominer' } },
  { label: 'expiring antibodies', method: 'get_antibody_library' },
];

export default function BobChat() {
  const { callMcp } = useApi();
  const [log, setLog] = useState([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [log.length]);

  const add = (role, text) => setLog(l => [...l, { role, text, ts: Date.now() }]);

  const exec = async (method, params) => {
    if (busy) return;
    setBusy(true);
    add('analyst', `> mcp ${method} ${JSON.stringify(params || {})}`);
    const res = await callMcp(method, params);
    const str = JSON.stringify(res?.result || res?.error || res, null, 2);
    add('bob', str);
    setBusy(false);
  };

  const onSubmit = (e) => {
    e.preventDefault();
    const val = input.trim();
    if (!val) return;
    setInput('');
    // Parse: "scenario:port_scan" etc
    if (val.toLowerCase().startsWith('scenario:')) {
      const scenario = val.split(':')[1]?.trim() || 'cryptominer';
      exec('run_simulation', { scenario });
    } else if (val.toLowerCase().startsWith('node:')) {
      const node_id = val.split(':')[1]?.trim() || 'node-beta';
      exec('get_node_detail', { node_id });
    } else if (val.toLowerCase().startsWith('quarantine:')) {
      const node_id = val.split(':')[1]?.trim() || 'node-beta';
      exec('quarantine_node', { node_id });
    } else if (val.toLowerCase().startsWith('release:')) {
      const node_id = val.split(':')[1]?.trim() || 'node-beta';
      exec('release_node', { node_id });
    } else if (val.toLowerCase().startsWith('blast:')) {
      const node_id = val.split(':')[1]?.trim() || 'node-beta';
      exec('get_blast_radius', { node_id });
    } else {
      exec('get_fleet_status');
    }
  };

  return (
    <div className="hacker-panel p-4 h-full flex flex-col">
      <div className="hacker-title text-sm mb-2">&gt; BOB // AI-POWERED SOC ANALYST</div>

      <div className="flex gap-2 flex-wrap mb-3">
        {QUICK.map(q => (
          <button
            key={q.label}
            disabled={busy}
            onClick={() => exec(q.method, q.params)}
            className="font-mono text-[10px] bg-hacker-panel border border-hacker-border text-hacker-blue px-2 py-1 rounded-hard hover:bg-hacker-blue hover:text-hacker-black transition-colors cursor-pointer disabled:opacity-40"
          >
            &gt; {q.label}
          </button>
        ))}
      </div>

      <div className="flex-1 bg-hacker-black border border-hacker-border rounded-hard p-3 overflow-y-auto font-mono text-[12px] min-h-[260px] max-h-[420px]">
        {log.map((entry, i) => (
          <div key={i} className={`mb-2 ${entry.role === 'analyst' ? 'text-right' : 'text-left'}`}>
            <div className={`inline-block rounded-hard px-3 py-1.5 max-w-[90%] text-left ${
              entry.role === 'analyst'
                ? 'border-l-2 border-hacker-green bg-hacker-panel text-hacker-white'
                : 'border-l-2 border-hacker-blue bg-hacker-panel text-hacker-white'
            }`}>
              <span className={`font-orbitron text-[9px] uppercase mr-1 ${entry.role === 'analyst' ? 'text-hacker-green' : 'text-hacker-blue'}`}>
                {entry.role === 'analyst' ? 'ANALYST >' : 'BOB >'}
              </span>
              <pre className="whitespace-pre-wrap text-[11px] font-mono break-words">{entry.text}</pre>
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
        {!log.length && (
          <div className="text-hacker-muted text-[11px]">{'>'} BOB online. Type a command or click a quick-action chip.</div>
        )}
      </div>

      <form onSubmit={onSubmit} className="mt-3 flex items-center gap-2">
        <span className="text-hacker-muted text-[11px] font-mono shrink-0">ANALYST:~$ </span>
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="scenario:port_scan | node:node-beta | quarantine:node-gamma"
          className="flex-1 bg-hacker-panel border border-hacker-border rounded-hard px-2 py-1.5 font-mono text-[12px] text-hacker-white placeholder-hacker-muted outline-none focus:border-hacker-green transition-colors"
          disabled={busy}
        />
        <button
          type="submit"
          disabled={busy}
          className="font-mono text-[11px] px-3 py-1.5 border border-hacker-green text-hacker-green rounded-hard uppercase tracking-wider hover:bg-hacker-green hover:text-hacker-black transition-colors cursor-pointer disabled:opacity-40"
        >
          [EXECUTE]
        </button>
      </form>
    </div>
  );
}