import { useStore } from '../store';
import { shortTime } from '../lib/format';

const TYPE_COLORS = {
  detection: '#FF2D2D',
  quarantine: '#FFB300',
  antibody: '#00B4D8',
  broadcast: '#00FF41',
  honeypot: '#7C3AED',
};

export default function Timeline() {
  const timeline = useStore(s => s.timeline);

  return (
    <div className="hacker-panel p-4 h-full overflow-y-auto">
      <div className="hacker-title text-sm mb-3">&gt; SWARM SENSE // EVENT TIMELINE</div>

      {!timeline.length ? (
        <div className="font-mono text-hacker-muted text-[11px]">{'>'} waiting for real-time events<span className="cursor" /></div>
      ) : (
        <div className="relative pl-6 space-y-4">
          <div className="absolute left-2.5 top-0 bottom-0 w-px border-l border-dashed border-hacker-border" />
          {timeline.slice(0, 50).map((ev, i) => {
            const color = TYPE_COLORS[ev.iconType] || TYPE_COLORS.broadcast;
            return (
              <div key={ev.id || i} className="relative animate-fade-in">
                <div
                  className="absolute -left-[13px] top-0.5 w-[20px] h-[20px] rounded-full flex items-center justify-center text-[9px] font-orbitron font-bold"
                  style={{ backgroundColor: `${color}22`, border: `1.5px solid ${color}`, color }}
                >
                  {ev.iconType === 'detection' ? '!' : ev.iconType === 'quarantine' ? 'Q' : ev.iconType === 'antibody' ? 'A' : ev.iconType === 'honeypot' ? 'H' : '*'}
                </div>
                <div className="font-mono text-hacker-muted text-[10px] -mt-0.5 mb-0.5">{shortTime(ev.timestamp)}</div>
                <div className="font-mono text-hacker-white text-[11px] leading-4">
                  {ev.title || ev.type || ev.severity || 'event'}
                </div>
                {ev.detail && (
                  <div className="font-mono text-hacker-muted text-[10px] mt-0.5">{ev.detail}</div>
                )}
                {ev.nodeId && ev.nodeId !== 'ALL' && (
                  <span className="inline-block mt-1 px-1.5 py-0.5 rounded-hard bg-hacker-border text-hacker-muted font-mono text-[9px]">{ev.nodeId}</span>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}