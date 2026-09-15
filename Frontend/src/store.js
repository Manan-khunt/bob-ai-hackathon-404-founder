import { create } from 'zustand';

let evtSeq = 0;

const INIT_NODES = [
  'node-alpha','node-beta','node-gamma','node-delta',
  'node-epsilon','node-zeta','node-eta','node-theta',
];

export const useStore = create((set, get) => ({
  booted: false,
  setBooted: () => set({ booted: true }),

  serverStartMs: Date.now(),

  immunity: { immunity_pct: 100, active_threats: 0, antibodies_today: 0, false_positive_rate: 0, total_threats_seen: 0, nodes_total: 8, antibodies_total: 0 },
  setImmunity: (d) => set({ immunity: { ...get().immunity, ...d } }),

  nodes: Object.fromEntries(INIT_NODES.map(n => [n, {
    agent_id: n,
    status: 'healthy',
    anomaly_score: 4.0,
    ip: '',
    antibodies_installed: [],
    last_seen: new Date().toISOString(),
    active_threat: null,
    biomarkers: {},
    neutralized_count: 0,
    owner_id: 'admin_1',
  }])),
  setNodes: (arr) => set({ nodes: Object.fromEntries(arr.map(n => [n.agent_id, n])) }),
  applyPatch: (nodeId, patch) => set(s => ({
    nodes: { ...s.nodes, [nodeId]: { ...(s.nodes[nodeId] || {}), ...patch } },
  })),

  timeline: [],
  pushTimeline: (evt) => set(s => {
    const entry = { id: evt.id || `t-${Date.now()}-${(evtSeq++)}`, iconType: evt.iconType || 'broadcast', ...evt };
    return { timeline: [entry, ...s.timeline].slice(0, 80) };
  }),

  antibodies: [],
  setAntibodies: (a) => set({ antibodies: a }),
  upsertAntibody: (ab) => set(s => {
    const idx = s.antibodies.findIndex(a => (a.id || a.antibody_id) === (ab.id || ab.antibody_id));
    if (idx >= 0) {
      const next = [...s.antibodies];
      next[idx] = ab;
      return { antibodies: next };
    }
    return { antibodies: [ab, ...s.antibodies] };
  }),

  honeypotEvents: [],
  setHoneypotEvents: (e) => set({ honeypotEvents: e }),
  addHoneypotEvent: (e) => set(s => ({ honeypotEvents: [e, ...s.honeypotEvents] })),

  incidents: [],
  setIncidents: (a) => set({ incidents: a }),

  selectedNodeId: null,
  selectNode: (id) => set({ selectedNodeId: id }),

  blastRadius: null,
  setBlastRadius: (b) => set({ blastRadius: b }),

  aptAttribution: null,
  setAptAttribution: (a) => set({ aptAttribution: a }),

  currentPage: 'dashboard',
  setPage: (p) => set({ currentPage: p }),
}));

export const iconForEventType = (type) => {
  if (!type) return 'broadcast';
  const t = String(type).toLowerCase();
  if (t.includes('quarantine') || t.includes('inflamm')) return 'quarantine';
  if (t.includes('detect') || t.includes('anomal')) return 'detection';
  if (t.includes('antibody') || t.includes('vaccin')) return 'antibody';
  if (t.includes('reset')) return 'broadcast';
  if (t.includes('neutral')) return 'antibody';
  return 'broadcast';
};