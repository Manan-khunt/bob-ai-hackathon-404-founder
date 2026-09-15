import HoneypotLog from '../components/HoneypotLog';
import Timeline from '../components/Timeline';
import useApi from '../hooks/useApi';
import { useState } from 'react';

const VECTORS = ['port_scan', 'cryptominer', 'c2_beacon', 'worm'];

export default function Honeypot() {
  const { triggerHoneypotAttack } = useApi();
  const [busy, setBusy] = useState(false);

  const fire = async (vec) => {
    setBusy(true);
    await triggerHoneypotAttack('185.220.101.4', vec);
    setBusy(false);
  };

  return (
    <div className="space-y-4">
      <div className="hacker-panel p-4 flex items-center justify-between">
        <span className="hacker-title text-sm">&gt; HONEYPOT // DECOY NODE OPS</span>
        <div className="flex gap-2">
          {VECTORS.map(v => (
            <button
              key={v}
              disabled={busy}
              onClick={() => fire(v)}
              className="font-mono text-[10px] bg-hacker-panel border border-hacker-purple/50 text-hacker-purple px-2 py-1 rounded-hard hover:bg-hacker-purple hover:text-hacker-black transition-colors cursor-pointer disabled:opacity-40"
            >
              fire {v.replace('_', ' ')}
            </button>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <HoneypotLog />
        <Timeline />
      </div>
    </div>
  );
}