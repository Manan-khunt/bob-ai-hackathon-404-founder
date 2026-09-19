import { create } from 'zustand';
import { INITIAL_ALERTS, INITIAL_INCIDENTS, OPERATIONAL_SOURCES, EXECUTIVE_METRICS } from './data/demoData';

export const useAppStore = create((set, get) => ({
  // Data sets
  alerts: INITIAL_ALERTS,
  incidents: INITIAL_INCIDENTS,
  sources: OPERATIONAL_SOURCES,
  metrics: EXECUTIVE_METRICS,

  // Selected entities
  selectedAlert: null,
  selectedIncidentId: 'INC-1042',
  selectedFalsePositive: null,
  isBobOpen: false,

  // Operational status
  operationalStatus: 'ELEVATED',
  operationalMode: 'LIVE INGESTION & CORRELATION',
  backendConnected: false,
  lastSyncTime: new Date(),

  // Demo Simulation State
  demoState: {
    active: false,
    scenarioName: null,
    currentStep: 0,
    totalSteps: 10,
    statusText: '',
    logs: [],
  },

  // Actions
  setAlerts: (alerts) => set({ alerts }),
  setIncidents: (incidents) => set({ incidents }),
  setSources: (sources) => set({ sources }),
  setMetrics: (metrics) => set({ metrics }),

  selectAlert: (alert) => set({ selectedAlert: alert }),
  closeAlertDrawer: () => set({ selectedAlert: null }),

  selectIncident: (id) => set({ selectedIncidentId: id }),

  selectFalsePositive: (alert) => set({ selectedFalsePositive: alert }),
  closeFalsePositiveModal: () => set({ selectedFalsePositive: null }),

  toggleBob: () => set((s) => ({ isBobOpen: !s.isBobOpen })),
  setBobOpen: (open) => set({ isBobOpen: open }),

  setBackendConnected: (connected) => set({ backendConnected: connected }),
  touchSync: () => set({ lastSyncTime: new Date() }),

  // Live Asset Isolation
  isolateAsset: (incidentId, assetId) => {
    set((state) => ({
      incidents: state.incidents.map((inc) => {
        if (inc.id === incidentId) {
          return {
            ...inc,
            affectedAssets: inc.affectedAssets.map((asset) =>
              asset.id === assetId ? { ...asset, status: 'Isolated (Encrypted Quarantine)' } : asset
            ),
          };
        }
        return inc;
      }),
    }));
  },

  // Demo Mode Simulation Orchestrator
  startCoordinatedIntrusionDemo: () => {
    const steps = [
      { step: 1, text: 'Step 1: Incoming SIEM alert (SYN probe on NODE-ALPHA)' },
      { step: 2, text: 'Step 2: Cyber Sensor alert (Covert TLS beaconing matching APT-29 profile)' },
      { step: 3, text: 'Step 3: Endpoint anomaly (lsass.exe memory dumping intercepted on NODE-BETA)' },
      { step: 4, text: 'Step 4: Intelligence report (Allied feed matches C2 IP to Operation GhostPulse)' },
      { step: 5, text: 'Step 5: IMMUNE-NET correlation engine links all 4 events across time & topology' },
      { step: 6, text: 'Step 6: AI triage classifies cluster as TRUE THREAT (96% Confidence)' },
      { step: 7, text: 'Step 7: Priority score calculated: 97/100 (CRITICAL DEFENCE PRIORITY)' },
      { step: 8, text: 'Step 8: MITRE ATT&CK techniques assigned: T1071 (C2), T1003 (Creds), T1210 (Lateral)' },
      { step: 9, text: 'Step 9: Commander BLUF generated with immediate isolation recommendation' },
      { step: 10, text: 'Step 10: Incident INC-1042 positioned at top of priority queue with armed countermeasures' },
    ];

    // Reset and initialize simulation
    set({
      demoState: {
        active: true,
        scenarioName: 'Coordinated Intrusion (Multi-Source APT)',
        currentStep: 1,
        totalSteps: 10,
        statusText: steps[0].text,
        logs: [steps[0].text],
      },
      selectedIncidentId: 'INC-1042',
      operationalStatus: 'CRITICAL',
    });

    let current = 1;
    const interval = setInterval(() => {
      current += 1;
      if (current <= 10) {
        set((state) => ({
          demoState: {
            ...state.demoState,
            currentStep: current,
            statusText: steps[current - 1].text,
            logs: [steps[current - 1].text, ...state.demoState.logs],
          },
          // Dynamic metric increments during simulation
          metrics: {
            ...state.metrics,
            totalAlerts: state.metrics.totalAlerts + 1,
            trueThreats: current >= 6 ? state.metrics.trueThreats : state.metrics.trueThreats,
          },
        }));
      } else {
        clearInterval(interval);
      }
    }, 1800);
  },

  startBenignNoiseDemo: () => {
    set({
      demoState: {
        active: true,
        scenarioName: 'Benign Noise Auto-Suppression',
        currentStep: 3,
        totalSteps: 3,
        statusText: 'Evaluated 1,147 isolated signals. 91.4% automatically suppressed as False Positives.',
        logs: [
          'Suppression Engine active across SIEM, Endpoint and OSINT feeds.',
          'Isolated alerts reconciled with authorized change requests and vendor checksums.',
          'Analyst workload reduced by 84.2%. Zero critical threats obscured.',
        ],
      },
      metrics: {
        ...get().metrics,
        falsePositives: 1147,
      },
    });
  },

  resetDemo: () => {
    set({
      alerts: INITIAL_ALERTS,
      incidents: INITIAL_INCIDENTS,
      metrics: EXECUTIVE_METRICS,
      selectedIncidentId: 'INC-1042',
      operationalStatus: 'ELEVATED',
      demoState: {
        active: false,
        scenarioName: null,
        currentStep: 0,
        totalSteps: 10,
        statusText: '',
        logs: [],
      },
    });
  },
}));

export const useStore = useAppStore;