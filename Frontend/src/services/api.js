/**
 * IMMUNE-NET API & Service Layer
 * Non-fatal backend integration with automatic fallback to synthetic intelligence
 */
import { INITIAL_ALERTS, INITIAL_INCIDENTS, OPERATIONAL_SOURCES, EXECUTIVE_METRICS } from '../data/demoData';

const API_BASE = 'http://localhost:8000';

async function safeFetch(endpoint, options = {}) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);
    const res = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    // Non-fatal, graceful fallback
    return null;
  }
}

export const apiService = {
  async getMetrics() {
    const data = await safeFetch('/api/stats');
    return data || EXECUTIVE_METRICS;
  },

  async getAlerts() {
    const data = await safeFetch('/api/alerts');
    return Array.isArray(data) && data.length > 0 ? data : INITIAL_ALERTS;
  },

  async getIncidents() {
    const data = await safeFetch('/incidents');
    return Array.isArray(data) && data.length > 0 ? data : INITIAL_INCIDENTS;
  },

  async getSources() {
    const data = await safeFetch('/api/sources');
    return Array.isArray(data) && data.length > 0 ? data : OPERATIONAL_SOURCES;
  },

  async getIncidentById(id) {
    const data = await safeFetch(`/api/incidents/${encodeURIComponent(id)}`);
    if (data) return data;
    return INITIAL_INCIDENTS.find(i => i.id === id) || INITIAL_INCIDENTS[0];
  },

  async isolateAsset(assetId) {
    return await safeFetch(`/api/quarantine/${encodeURIComponent(assetId)}`, { method: 'POST' });
  },

  async releaseAsset(assetId) {
    return await safeFetch(`/api/release/${encodeURIComponent(assetId)}`, { method: 'POST' });
  },
};
