import { useEffect } from 'react';
import { HashRouter, Routes, Route } from 'react-router-dom';
import { useStore } from './store';
import useWebSocket from './hooks/useWebSocket';
import useApi from './hooks/useApi';
import TerminalBoot from './components/TerminalBoot';
import MatrixRain from './components/MatrixRain';
import Sidebar from './components/Sidebar';
import StatBar from './components/StatBar';
import Dashboard from './pages/Dashboard';
import Nodes from './pages/Nodes';
import Incidents from './pages/Incidents';
import Antibodies from './pages/Antibodies';
import Honeypot from './pages/Honeypot';
import BobPage from './pages/BobPage';
import Investigation from './pages/Investigation';
import ErrorBoundary from './components/ErrorBoundary';

function AppShell() {
  const booted = useStore(s => s.booted);
  const { refreshAll, startPolling, refreshIncidents } = useApi();

  useWebSocket();

  useEffect(() => {
    refreshAll();
    refreshIncidents();
    startPolling(3000);
    const longPoll = setInterval(() => refreshIncidents(), 5000);
    return () => clearInterval(longPoll);
  }, [refreshAll, startPolling, refreshIncidents]);

  if (!booted) return <TerminalBoot />;

  return (
    <div className="relative min-h-screen bg-hacker-black text-hacker-white font-mono">
      <MatrixRain />
      <Sidebar />
      <div className="ml-14 min-h-screen flex flex-col">
        <StatBar />
        <main className="flex-1 p-4 lg:p-6">
          <ErrorBoundary label="ROUTE">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/nodes" element={<Nodes />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/investigation" element={<Investigation />} />
              <Route path="/antibodies" element={<Antibodies />} />
              <Route path="/honeypot" element={<Honeypot />} />
              <Route path="/bob" element={<BobPage />} />
            </Routes>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <HashRouter>
      <AppShell />
    </HashRouter>
  );
}