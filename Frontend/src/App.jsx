import React, { useEffect } from 'react';
import { HashRouter, Routes, Route } from 'react-router-dom';
import AppLayout from './components/layout/AppLayout';
import DashboardPage from './pages/DashboardPage';
import AlertsPage from './pages/AlertsPage';
import IncidentsPage from './pages/IncidentsPage';
import MitrePage from './pages/MitrePage';
import BlufPage from './pages/BlufPage';
import SourcesPage from './pages/SourcesPage';
import BobPage from './pages/BobPage';
import SettingsPage from './pages/SettingsPage';
import { useAppStore } from './store';
import { apiService } from './services/api';

export default function App() {
  const setMetrics = useAppStore((s) => s.setMetrics);
  const setBackendConnected = useAppStore((s) => s.setBackendConnected);
  const touchSync = useAppStore((s) => s.touchSync);

  useEffect(() => {
    // Non-fatal background sync with backend if running
    let mounted = true;
    async function initTelemetry() {
      try {
        const metrics = await apiService.getMetrics();
        if (mounted && metrics) {
          setMetrics(metrics);
          setBackendConnected(true);
          touchSync();
        }
      } catch {
        // Fallback is active in store
        if (mounted) setBackendConnected(false);
      }
    }

    initTelemetry();
    const interval = setInterval(initTelemetry, 8000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, [setMetrics, setBackendConnected, touchSync]);

  return (
    <HashRouter>
      <AppLayout>
        <Routes>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/mitre" element={<MitrePage />} />
          <Route path="/bluf" element={<BlufPage />} />
          <Route path="/sources" element={<SourcesPage />} />
          <Route path="/bob" element={<BobPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          {/* Wildcard fallback */}
          <Route path="*" element={<DashboardPage />} />
        </Routes>
      </AppLayout>
    </HashRouter>
  );
}