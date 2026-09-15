import { useEffect, useRef } from 'react';
import { useStore, iconForEventType } from '../store';

const API = 'http://localhost:8000';

export default function useWebSocket() {
  const wsRef = useRef(null);
  const applyPatch = useStore(s => s.applyPatch);
  const pushTimeline = useStore(s => s.pushTimeline);
  const upsertAntibody = useStore(s => s.upsertAntibody);
  const setImmunity = useStore(s => s.setImmunity);
  const setBlastRadius = useStore(s => s.setBlastRadius);
  const addHoneypotEvent = useStore(s => s.addHoneypotEvent);

  useEffect(() => {
    let closed = false;
    function connect() {
      if (closed) return;
      const url = 'ws://localhost:8000/ws';
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'HEARTBEAT' }));
      };

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data);
          if (msg.type === 'NODE_UPDATE') {
            applyPatch(msg.nodeId, msg.patch);
          } else if (msg.type === 'IMMUNE_EVENT') {
            const ev = msg.event || msg;
            pushTimeline({ iconType: iconForEventType(ev.type), ...ev });
            // Update stats from herd_immunity
            if (ev.type === 'HERD_IMMUNITY' && ev.metadata?.coverage_pct != null) {
              setImmunity({ immunity_pct: ev.metadata.coverage_pct });
            }
          } else if (msg.type === 'NEW_ANTIBODY') {
            upsertAntibody(msg.antibody);
            pushTimeline({
              iconType: 'antibody',
              title: 'Antibody Received',
              detail: msg.antibody?.name || msg.antibody?.antibody_id || '',
              timestamp: new Date().toISOString(),
            });
          } else if (msg.type === 'anomaly_detected') {
            applyPatch(msg.node_id, { status: 'infected', anomaly_score: msg.anomaly_score, active_threat: msg.threat_type });
            pushTimeline({ iconType: 'detection', title: `ANOMALY DETECTED: ${msg.threat_type}`, detail: msg.node_id, timestamp: msg.timestamp, nodeId: msg.node_id });
          } else if (msg.type === 'quarantine_issued') {
            applyPatch(msg.node_id, { status: 'quarantined' });
            pushTimeline({ iconType: 'quarantine', title: 'QUARANTINE ISSUED', detail: msg.reason || msg.node_id, timestamp: msg.timestamp, nodeId: msg.node_id });
          } else if (msg.type === 'antibody_broadcast') {
            pushTimeline({ iconType: 'antibody', title: 'ANTIBODY BROADCAST', detail: `Threat: ${msg.threat_type}`, timestamp: msg.timestamp });
          } else if (msg.type === 'herd_immunity') {
            setImmunity({ immunity_pct: msg.coverage_pct });
          } else if (msg.type === 'blast_radius') {
            setBlastRadius(msg);
            pushTimeline({ iconType: 'quarantine', title: 'BLAST RADIUS PREDICTED', detail: `Infected: ${msg.infected_node}`, timestamp: msg.timestamp, severity: msg.severity });
          } else if (msg.type === 'honeypot_hit' || msg.type === 'HONEYPOT_HIT') {
            addHoneypotEvent(msg);
            pushTimeline({ iconType: 'detection', title: 'HONEYPOT CAPTURED', detail: `${msg.attack_vector} from ${msg.source_ip || ''}`, timestamp: msg.timestamp || msg.detected_at, nodeId: msg.node_id });
          } else if (msg.type === 'APT_IDENTIFIED') {
            pushTimeline({ iconType: 'detection', title: 'APT ATTRIBUTED', detail: msg.actor_name || '', timestamp: msg.timestamp });
          } else if (msg.type === 'REVACCINATION' || msg.type === 'ANTIBODY_NEUTRALIZATION') {
            pushTimeline({ iconType: 'antibody', title: msg.title || msg.type, detail: msg.detail || '', timestamp: msg.timestamp || new Date().toISOString() });
          } else if (msg.type === 'RESET_BASELINE' || msg.type === 'NETWORK_RESET') {
            pushTimeline({ iconType: 'broadcast', title: msg.title || msg.type, detail: msg.detail || '', timestamp: msg.timestamp || new Date().toISOString() });
          } else if (msg.type === 'PONG') {
            // heartbeat ack
          }
        } catch {
          // ignore non-json
        }
      };

      ws.onerror = () => {};
      ws.onclose = () => {
        if (!closed) setTimeout(connect, 2500);
      };
    }

    connect();
    return () => { closed = true; wsRef.current?.close(); };
  }, [applyPatch, pushTimeline, upsertAntibody, setImmunity, setBlastRadius, addHoneypotEvent]);
}