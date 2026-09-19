import { useEffect, useState } from 'react';
import { useStore } from '../store';

function pad(n) {
  return String(n).padStart(2, '0');
}

export default function KPIBar() {
  const immunity = useStore(s => s.immunity) ?? {};
  const incidents = useStore(s => s.incidents) ?? [];
  const honeypotEvents = useStore(s => s.honeypotEvents) ?? [];
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const uptimeSecs = Math.floor((now - useStore.getState().serverStartMs) / 1000);
  const uptime = `${pad(Math.floor(uptimeSecs / 3600))}:${pad(Math.floor((uptimeSecs % 3600) / 60))}:${pad(uptimeSecs % 60)}`;

  // Safe defensive calculations
  const totalAlerts = Array.isArray(incidents) ? incidents.length : 0;
  const correlatedIncidents = Array.isArray(incidents)
    ? incidents.filter(i => i?.correlationStatus === 'CORRELATED').length
    : 0;
  const confirmedThreats = Array.isArray(incidents)
    ? incidents.filter(i => i?.classification === 'TRUE_THREAT').length
    : 0;
  const falsePositives = Array.isArray(incidents)
    ? incidents.filter(i => i?.classification === 'FALSE_POSITIVE').length
    : 0;
  const criticalIncidents = Array.isArray(incidents)
    ? incidents.filter(i => i?.severity && i.severity.toUpperCase() === 'CRITICAL').length
    : 0;
  const activeSources = Array.isArray(incidents)
    ? new Set(incidents.map(i => i?.source).filter(Boolean)).size
    : 0;

  const cards = [
    { label: 'TOTAL ALERTS', value: String(totalAlerts), critical: false, color: '#38BDF8' },
    { label: 'CORRELATED INCIDENTS', value: String(correlatedIncidents), critical: false, color: '#A78BFA' },
    { label: 'TRUE THREATS', value: String(confirmedThreats), critical: confirmedThreats > 0, color: confirmedThreats > 0 ? '#EF4444' : '#22C55E' },
    { label: 'FALSE POSITIVES', value: String(falsePositives), critical: false, color: '#F59E0B' },
    { label: 'CRITICAL THREATS', value: String(criticalIncidents), critical: criticalIncidents > 0, color: criticalIncidents > 0 ? '#EF4444' : '#94A3B8' },
    { label: 'ACTIVE SOURCES', value: String(activeSources), critical: false, color: '#38BDF8' },
  ];

  return (
    <div style={{ borderBottom: '1px solid #1E293B', padding: '0.75rem 1.5rem', background: '#0F172A' }}>
      {/* Title bar */}
      <div style={{ marginBottom: '0.75rem', display: 'flex', alignItems: 'baseline', gap: '0.75rem', flexWrap: 'wrap' }}>
        <h1 style={{
          fontFamily: "'Orbitron', sans-serif",
          fontWeight: 900,
          fontSize: '1.125rem',
          color: '#38BDF8',
          margin: 0,
          letterSpacing: '0.12em',
        }}>
          IMMUNE-NET
        </h1>
        <span style={{
          fontFamily: "'Orbitron', sans-serif",
          fontSize: '0.55rem',
          color: '#64748B',
          letterSpacing: '0.18em',
          fontWeight: 500,
        }}>
          MULTI-SOURCE THREAT FUSION &amp; COMMAND INTELLIGENCE
        </span>
        <span style={{ marginLeft: 'auto', fontFamily: 'monospace', fontSize: '0.7rem', color: '#475569' }}>
          UPTIME {uptime}
        </span>
      </div>

      {/* KPI cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '0.5rem' }}>
        {cards.map(c => (
          <div
            key={c.label}
            style={{
              background: '#0B1120',
              border: `1px solid ${c.critical ? '#EF4444' : '#1E3A5F'}`,
              borderRadius: '6px',
              padding: '0.5rem 0.75rem',
              transition: 'border-color 0.2s',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
              <span style={{ fontFamily: 'monospace', fontSize: '0.6rem', color: '#475569', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
                {c.label}
              </span>
              <span
                style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  background: c.critical ? '#EF4444' : '#22C55E',
                  animation: c.critical ? 'blink 0.6s step-end infinite' : 'blink 2s step-end infinite',
                  display: 'inline-block',
                }}
              />
            </div>
            <div style={{
              fontFamily: "'Orbitron', sans-serif",
              fontWeight: 700,
              fontSize: '1.375rem',
              color: c.color,
              lineHeight: 1,
            }}>
              {c.value}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
