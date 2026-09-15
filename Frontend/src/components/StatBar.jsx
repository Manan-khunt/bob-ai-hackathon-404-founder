import { useEffect, useState } from 'react';
import { useStore } from '../store';

function pad(n) {
  return String(n).padStart(2, '0');
}

export default function StatBar() {
  const immunity = useStore(s => s.immunity);
  const antibodiesTotal = useStore(s => s.antibodies.length);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const uptimeSecs = Math.floor((now - useStore.getState().serverStartMs) / 1000);
  const uptime = `${pad(Math.floor(uptimeSecs / 3600))}:${pad(Math.floor((uptimeSecs % 3600) / 60))}:${pad(uptimeSecs % 60)}`;

  const cards = [
    { label: 'FLEET IMMUNITY', value: `${immunity.immunity_pct ?? 100}%`, critical: false },
    { label: 'ACTIVE THREATS', value: String(immunity.active_threats ?? 0), critical: (immunity.active_threats ?? 0) > 0 },
    { label: 'ANTIBODIES TODAY', value: String(immunity.antibodies_today ?? antibodiesTotal), critical: false },
    { label: 'BLOCK RATE', value: '100%', critical: false },
    { label: 'UPTIME', value: uptime, critical: false },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 px-4 lg:px-6 pt-4">
      {cards.map(c => (
        <div key={c.label} className="hacker-panel px-3 py-2.5">
          <div className="flex items-center justify-between">
            <span className="label-muted">{c.label}</span>
            <span
              className={`inline-block w-2 h-2 rounded-full animate-blink ${c.critical ? 'bg-hacker-red' : 'bg-hacker-green'}`}
              style={{ animationDuration: c.critical ? '0.6s' : '1.6s' }}
            />
          </div>
          <div className="font-orbitron font-bold text-hacker-green text-[26px] leading-none mt-1">{c.value}</div>
        </div>
      ))}
    </div>
  );
}