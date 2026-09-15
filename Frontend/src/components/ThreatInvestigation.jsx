import { useEffect, useState } from 'react';
import { useStore } from '../store';
import useApi from '../hooks/useApi';
import { NODE_DISPLAY, shortTime } from '../lib/format';

function Section({ label, children }) {
  return (
    <div className="hacker-panel p-4">
      <div className="hacker-title text-sm mb-3">{label}</div>
      {children}
    </div>
  );
}

function Field({ k, v, tone = '' }) {
  const color = tone === 'red' ? 'text-hacker-red' : tone === 'amber' ? 'text-hacker-amber' : tone === 'green' ? 'text-hacker-green' : 'text-hacker-white';
  return (
    <div className="flex justify-between gap-4 py-1 border-b border-hacker-border/40">
      <span className="label-muted">{k}</span>
      <span className={`font-mono text-[11px] ${color} text-right`}>{v}</span>
    </div>
  );
}

function ContributionBar({ c }) {
  const pct = Math.min(100, Math.round((c.normalized_contribution || 0) * 100));
  const color = pct >= 40 ? '#FF2D2D' : pct >= 25 ? '#FFB300' : '#00B4D8';
  return (
    <div className="space-y-1">
      <div className="flex justify-between font-mono text-[10px]">
        <span className="text-hacker-white/80 uppercase">{(c.feature || 'feature').replace(/_/g, ' ')}</span>
        <span style={{ color }}>
          {typeof c.value === 'number' ? (c.value < 100 && c.value % 1 !== 0 ? c.value.toFixed(2) : c.value) : c.value}
          {' '}· {pct}%
        </span>
      </div>
      <div className="h-2 rounded-full bg-hacker-border overflow-hidden">
        <div className="h-full" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
      <div className="font-mono text-[10px] text-hacker-muted leading-4">{c.reason}</div>
    </div>
  );
}

export default function ThreatInvestigation() {
  const incidents = useStore(s => s.incidents);
  const { fetchIncidentBriefing } = useApi();
  const [briefing, setBriefing] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedId, setSelectedId] = useState(null);

  const latestId = incidents[0]?.incident_id;
  const activeId = selectedId || latestId;

  useEffect(() => {
    if (!activeId) { setBriefing(null); return; }
    let cancelled = false;
    const run = async () => {
      setLoading(true);
      const data = await fetchIncidentBriefing(activeId);
      if (!cancelled) setBriefing(data);
      setLoading(false);
    };
    run();
    return () => { cancelled = true; };
  }, [activeId, incidents, fetchIncidentBriefing]);

  if (!incidents.length) {
    return (
      <div className="hacker-panel p-6">
        <div className="hacker-title text-sm mb-2">&gt; THREAT INVESTIGATION // COMMANDER VIEW</div>
        <div className="font-mono text-hacker-muted text-[11px]">
          awaiting confirmed incident... the next detection will be broken down here for immediate commander triage.
        </div>
      </div>
    );
  }

  const th = briefing?.threat || {};
  const why = briefing?.why || {};
  const what = briefing?.what_happened || {};
  const impact = briefing?.impact || {};
  const resp = briefing?.response || {};

  const explanation = why.explanation || [];
  const apt = what.apt_fingerprint || [];
  const blastChain = impact.blast_radius?.propagation_chain || [];
  const nodeInfo = NODE_DISPLAY[th.node_id] || { icon: '?', color: '#00FF41' };

  const sevColor = th.severity === 'critical' ? '#FF2D2D' : th.severity === 'high' ? '#FFB300' : '#00FF41';

  return (
    <div className="space-y-4">
      {/* Header + incident selector */}
      <div className="hacker-panel p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="hacker-title text-sm">&gt; THREAT INVESTIGATION // COMMANDER VIEW</div>
        <select
          value={activeId}
          onChange={e => setSelectedId(e.target.value)}
          className="bg-hacker-panel border border-hacker-border rounded-hard text-hacker-white font-mono text-[11px] px-2 py-1 cursor-pointer"
        >
          {incidents.slice(0, 10).map(inc => (
            <option key={inc.incident_id} value={inc.incident_id}>
              {inc.scenario} @ {inc.node_id}
            </option>
          ))}
        </select>
      </div>

      {loading && !briefing && <div className="font-mono text-hacker-muted text-[11px]">compiling briefing...</div>}

      {/* THREAT */}
      <Section label="> THREAT">
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          <div className="bg-hacker-panel border border-hacker-border rounded-hard p-3 col-span-2 lg:col-span-2">
            <div className="label-muted mb-1">THREAT TYPE</div>
            <div className="font-orbitron font-bold text-hacker-red text-sm">{th.classification || th.threat_type}</div>
            <div className="font-mono text-hacker-muted text-[11px] mt-1">node {th.node_id}</div>
          </div>
          <div className="bg-hacker-panel border border-hacker-border rounded-hard p-3">
            <div className="label-muted mb-1">SEVERITY</div>
            <div className="font-orbitron font-bold text-sm" style={{ color: sevColor }}>
              {(th.severity || 'unknown').toUpperCase()}
            </div>
          </div>
          <div className="bg-hacker-panel border border-hacker-border rounded-hard p-3">
            <div className="label-muted mb-1">CONFIDENCE</div>
            <div className="font-orbitron font-bold text-sm text-hacker-green">
              {th.confidence != null ? `${Math.round(Number(th.confidence) * 100)}%` : '--'}
            </div>
          </div>
          <div className="bg-hacker-panel border border-hacker-border rounded-hard p-3">
            <div className="label-muted mb-1">DETECTED</div>
            <div className="font-orbitron font-bold text-sm text-hacker-amber">{shortTime(th.detected_at)}</div>
          </div>
        </div>
      </Section>

      {/* WHY */}
      <Section label="> WHY? // ANOMALY CONTRIBUTION ANALYSIS">
        {explanation.length > 0 ? (
          <>
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-3 mb-3">
              {explanation.filter(c => !['process_name', 'destination'].includes(c.feature)).slice(0, 3).map(c => (
                <ContributionBar key={c.feature} c={c} />
              ))}
            </div>
            {(why.summary || '') && (
              <div className="font-mono text-hacker-green text-[11px] leading-5 mt-1">{why.summary}</div>
            )}
            {explanation.filter(c => ['process_name', 'destination'].includes(c.feature)).map(c => (
              <div key={c.feature} className="font-mono text-hacker-white/70 text-[10px] mt-1">
                &gt; {(c.feature || 'feature').replace('_', ' ')}: {c.value} — {c.reason}
              </div>
            ))}
            {why.anomaly_score != null && (
              <div className="font-mono text-hacker-muted text-[10px] mt-2">
                ML anomaly score: {Number(why.anomaly_score).toFixed(1)}/100
              </div>
            )}
          </>
        ) : (
          <div className="font-mono text-hacker-muted text-[11px]">{why.summary || 'no explanation on record'}</div>
        )}
      </Section>

      {/* WHAT HAPPENED */}
      <Section label="> WHAT HAPPENED?">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div>
            <div className="label-muted mb-1">MITRE ATT&CK</div>
            <div className="font-orbitron font-bold text-hacker-green text-sm">
              {what.mitre?.technique_id} — {what.mitre?.technique_name}
            </div>
            <div className="font-mono text-hacker-muted text-[11px]">{what.mitre?.tactic}</div>
          </div>
          <div>
            <div className="label-muted mb-1">APT FINGERPRINT</div>
            {apt.length > 0 ? (
              <div className="space-y-1">
                {apt.slice(0, 2).map(a => (
                  <div key={a.name} className="font-mono text-[11px] text-hacker-red">
                    &gt; {a.name} ({Math.round(a.confidence_pct)}%)
                  </div>
                ))}
              </div>
            ) : (
              <div className="font-mono text-hacker-muted text-[11px]">unclassified</div>
            )}
          </div>
          <div>
            <div className="label-muted mb-1">OBSERVED BEHAVIOR</div>
            <div className="font-mono text-[11px] text-hacker-white/70 leading-5 whitespace-pre-wrap max-h-28 overflow-y-auto">
              {what.bluf_summary?.split('\n').slice(0, 3).join('\n') || 'n/a'}
            </div>
          </div>
        </div>
      </Section>

      {/* IMPACT */}
      <Section label="> IMPACT">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div>
            <div className="label-muted mb-2">BLAST RADIUS</div>
            <div className="flex items-end gap-2 overflow-x-auto pb-2">
              {[
                impact.blast_radius?.infected_node
                  ? { node_id: impact.blast_radius.infected_node, estimated_seconds_to_fall: null }
                  : null,
                ...blastChain,
              ].filter(Boolean).map((e, i) => {
                const nodeId = e.node_id || 'unknown';
                const disp = NODE_DISPLAY[nodeId] || { icon: '?', color: '#00FF41' };
                const secs = e.estimated_seconds_to_fall;
                const color = i === 0 ? '#FF2D2D' : secs != null && secs < 15 ? '#FF2D2D' : secs != null && secs < 60 ? '#FFB300' : '#00B4D8';
                return (
                  <div key={`${nodeId}-${i}`} className="flex flex-col items-center w-12">
                    <div className="w-6 h-6 rounded-full border-2 flex items-center justify-center font-orbitron text-[11px]"
                      style={{ borderColor: color, color, boxShadow: `0 0 8px ${color}55` }}>
                      {disp.icon}
                    </div>
                    <div className="font-mono text-[9px] text-hacker-muted mt-1">{nodeId.replace('node-', '')}</div>
                    <div className="font-mono text-[9px]" style={{ color }}>
                      {i === 0 ? 'P0' : `fall ${secs}s`}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
          <div>
            <Field k="AFFECTED HOSTS" v={impact.affected_hosts ?? 1} />
            <Field k="LATERAL MOVEMENT" v={impact.lateral_movement_status || 'n/a'}
              tone={String(impact.lateral_movement_status || '').includes('none') ? 'green' : 'red'} />
            <Field k="PRE-EMPTIVE QUARANTINE" v={impact.blast_radius?.preemptive_quarantined?.length || 0} />
          </div>
        </div>
      </Section>

      {/* RESPONSE */}
      <Section label="> RESPONSE">
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          <div className="bg-hacker-panel border border-hacker-border rounded-hard p-3">
            <div className="label-muted mb-1">DETECTION</div>
            <div className="font-mono text-[11px] text-hacker-green">{resp.detection_model || 'isolation-forest-v1.0'}</div>
          </div>
          <div className="bg-hacker-panel border border-hacker-border rounded-hard p-3">
            <div className="label-muted mb-1">CONTAINMENT</div>
            <div className="font-mono text-[11px] text-hacker-red">{resp.containment || 'autonomous quarantine issued'}</div>
          </div>
          <div className="bg-hacker-panel border border-hacker-border rounded-hard p-3">
            <div className="label-muted mb-1">REMEDIATION</div>
            <div className="font-mono text-[11px] text-hacker-amber">{resp.antibody_generated ? 'digital antibody synthesized' : 'pending synthesis'}</div>
          </div>
          <div className="bg-hacker-panel border border-hacker-border rounded-hard p-3">
            <div className="label-muted mb-1">ANTIBODY</div>
            <div className="font-mono text-[11px] text-hacker-green truncate">{resp.antibody_id || 'n/a'}</div>
          </div>
          <div className="bg-hacker-panel border border-hacker-border rounded-hard p-3">
            <div className="label-muted mb-1">HERD IMMUNITY</div>
            <div className="font-mono text-[11px] text-hacker-green">{resp.herd_immunity_status || 'active'}</div>
          </div>
        </div>
      </Section>
    </div>
  );
}