import { useStore } from '../store';

const LIFECYCLE = [
  { title: 'Threat Detected', detail: 'IsolationForest flags anomalous telemetry', color: '#FF2D2D' },
  { title: 'Threat Analyzed', detail: 'Correlator maps evidence to MITRE + APT', color: '#FFB300' },
  { title: 'Antibody Generated', detail: 'Signed digital antibody synthesized', color: '#00B4D8' },
  { title: 'Threat Contained', detail: 'Autonomous quarantine command issued', color: '#FFB300' },
  { title: 'Fingerprint Stored', detail: 'eBPF rule persisted to immune memory', color: '#00FF41' },
  { title: 'Immune Memory Updated', detail: 'Fleet-wide distribution via WebSocket', color: '#00FF41' },
  { title: 'Future Detections Accelerated', detail: 'Repeat attacks blocked sub-2ms', color: '#7C3AED' },
];

export default function ImmuneLifecycle() {
  const antibodies = useStore(s => s.antibodies);
  const immunity = useStore(s => s.immunity);

  return (
    <div className="hacker-panel p-4">
      <div className="hacker-title text-sm mb-3">&gt; DIGITAL ANTIBODY // IMMUNE MEMORY LIFECYCLE</div>

      <div className="space-y-0">
        {LIFECYCLE.map((step, i) => (
          <div key={step.title} className="flex gap-3">
            <div className="flex flex-col items-center">
              <div
                className="w-4 h-4 rounded-full border-2 mt-0.5"
                style={{ borderColor: step.color, boxShadow: `0 0 6px ${step.color}66` }}
              />
              {i < LIFECYCLE.length - 1 && <div className="w-px flex-1 my-1" style={{ backgroundColor: step.color, opacity: 0.4 }} />}
            </div>
            <div className="pb-3">
              <div className="font-orbitron text-[11px] font-bold" style={{ color: step.color }}>
                {String(i + 1).padStart(2, '0')} // {step.title.toUpperCase()}
              </div>
              <div className="font-mono text-hacker-muted text-[10px] leading-4">{step.detail}</div>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-3 pt-3 border-t border-hacker-border grid grid-cols-2 gap-2 font-mono text-[11px]">
        <div className="flex justify-between"><span className="text-hacker-muted">Active antibodies</span><span className="text-hacker-green">{immunity.antibodies_total ?? antibodies.length}</span></div>
        <div className="flex justify-between"><span className="text-hacker-muted">Fleet immunity</span><span className="text-hacker-green">{immunity.immunity_pct ?? 0}%</span></div>
        <div className="flex justify-between"><span className="text-hacker-muted">Threats seen</span><span className="text-hacker-amber">{immunity.total_threats_seen ?? 0}</span></div>
        <div className="flex justify-between"><span className="text-hacker-muted">Deflections</span><span className="text-hacker-red">{immunity.block_rate ?? '--'}</span></div>
      </div>
    </div>
  );
}