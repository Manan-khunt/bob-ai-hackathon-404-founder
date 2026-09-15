import { useCallback, useRef } from 'react';
import { useStore } from '../store';

const API = 'http://localhost:8000';

async function api(path, opts) {
  try {
    const res = await fetch(`${API}${path}`, opts);
    if (!res.ok) throw new Error(res.status);
    return await res.json();
  } catch (e) {
    console.warn(`[API] ${path} failed`, e);
    return null;
  }
}

export default function useApi() {
  const setNodes = useStore(s => s.setNodes);
  const setImmunity = useStore(s => s.setImmunity);
  const setAntibodies = useStore(s => s.setAntibodies);
  const setHoneypotEvents = useStore(s => s.setHoneypotEvents);
  const setIncidents = useStore(s => s.setIncidents);
  const setBlastRadius = useStore(s => s.setBlastRadius);
  const setAptAttribution = useStore(s => s.setAptAttribution);
  const applyPatch = useStore(s => s.applyPatch);
  const pushTimeline = useStore(s => s.pushTimeline);
  const intervalRef = useRef(null);

  const refreshStats = useCallback(async () => {
    const stats = await api('/api/stats');
    if (stats) setImmunity(stats);
  }, [setImmunity]);

  const refreshNodes = useCallback(async () => {
    const nodes = await api('/api/nodes');
    if (Array.isArray(nodes)) setNodes(nodes);
  }, [setNodes]);

  const refreshAntibodies = useCallback(async () => {
    const abs = await api('/api/antibodies');
    if (Array.isArray(abs)) setAntibodies(abs);
  }, [setAntibodies]);

  const refreshHoneypot = useCallback(async () => {
    const evts = await api('/api/honeypot/events');
    if (Array.isArray(evts)) setHoneypotEvents(evts);
  }, [setHoneypotEvents]);

  const refreshIncidents = useCallback(async () => {
    const inc = await api('/incidents');
    if (Array.isArray(inc)) setIncidents(inc);
  }, [setIncidents]);

  const fetchBlastRadius = useCallback(async (nodeId) => {
    const data = await api(`/api/blast-radius/${encodeURIComponent(nodeId)}`);
    if (data) setBlastRadius(data);
    return data;
  }, [setBlastRadius]);

  const fetchAptAttribution = useCallback(async (incidentId) => {
    const data = await api(`/api/apt-fingerprint/${encodeURIComponent(incidentId)}`);
    if (data) setAptAttribution(data);
    return data;
  }, [setAptAttribution]);

  const fetchIncidentBriefing = useCallback(async (incidentId) => {
    return api(`/api/incidents/${encodeURIComponent(incidentId)}/briefing`);
  }, []);

  const callMcp = useCallback(async (method, params = {}) => {
    return api('/mcp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: Date.now(), method, params }),
    });
  }, []);

  const triggerAttack = useCallback(async (nodeId, scenario) => {
    const res = await api('/api/demo/attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_node: nodeId || 'node-beta', scenario: scenario || 'cryptominer', mode: 'first_attack' }),
    });
    return res;
  }, []);

  const quarantineNode = useCallback(async (nodeId) => {
    await api(`/api/quarantine/${encodeURIComponent(nodeId)}`, { method: 'POST' });
    applyPatch(nodeId, { status: 'quarantined' });
  }, [applyPatch]);

  const releaseNode = useCallback(async (nodeId) => {
    await api(`/api/release/${encodeURIComponent(nodeId)}`, { method: 'POST' });
    applyPatch(nodeId, { status: 'healthy', active_threat: null });
  }, [applyPatch]);

  const triggerHoneypotAttack = useCallback(async (sourceIp = '185.220.101.4', attackVector = 'port_scan') => {
    const res = await api('/api/honeypot/attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source_ip: sourceIp, attack_vector: attackVector }),
    });
    refreshHoneypot();
    return res;
  }, [refreshHoneypot]);

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshStats(), refreshNodes(), refreshAntibodies(), refreshIncidents(), refreshHoneypot()]);
  }, [refreshStats, refreshNodes, refreshAntibodies, refreshIncidents, refreshHoneypot]);

  const startPolling = useCallback((ms = 3000) => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    intervalRef.current = setInterval(() => {
      refreshStats();
      refreshAntibodies();
      refreshNodes();
    }, ms);
  }, [refreshStats, refreshAntibodies, refreshNodes]);

  const stopPolling = useCallback(() => {
    if (intervalRef.current) clearInterval(intervalRef.current);
  }, []);

  return {
    refreshStats, refreshNodes, refreshAntibodies, refreshHoneypot,
    refreshIncidents, fetchBlastRadius, fetchAptAttribution, fetchIncidentBriefing,
    callMcp, triggerAttack, quarantineNode, releaseNode,
    triggerHoneypotAttack, refreshAll, startPolling, stopPolling,
  };
}