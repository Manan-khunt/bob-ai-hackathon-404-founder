import React, { useState } from 'react';
import { Settings, Sliders, Shield, Database, Save, Check } from 'lucide-react';

export default function SettingsPage() {
  const [correlationThreshold, setCorrelationThreshold] = useState(85);
  const [autoQuarantine, setAutoQuarantine] = useState(true);
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-[1000px] mx-auto pb-12">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-defence">
        <div className="flex items-center gap-2 mb-1">
          <Settings className="w-5 h-5 text-sky-400" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            SYSTEM CALIBRATION &amp; FUSION POLICY
          </h2>
        </div>
        <p className="text-xs text-slate-400">
          Configure multi-source correlation thresholds, autonomous quarantine policies, and backend telemetry endpoints.
        </p>
      </div>

      {/* Settings Sections */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-6 shadow-defence text-xs">
        {/* Correlation Engine Settings */}
        <div>
          <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-2">
            <Sliders className="w-4 h-4 text-sky-400" />
            Correlation Engine Sensitivity
          </h3>
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-4">
            <div>
              <div className="flex justify-between font-medium mb-1">
                <span className="text-slate-200">Incident Auto-Escalation Threshold</span>
                <span className="font-mono text-sky-400 font-bold">{correlationThreshold}%</span>
              </div>
              <input
                type="range"
                min="50"
                max="99"
                value={correlationThreshold}
                onChange={(e) => setCorrelationThreshold(Number(e.target.value))}
                className="w-full accent-sky-500 cursor-pointer"
              />
              <div className="text-[11px] text-slate-400 mt-1">
                Alert clusters with cross-source agreement exceeding {correlationThreshold}% are automatically promoted to TRUE THREAT status.
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between">
              <div>
                <div className="font-semibold text-slate-200">Autonomous Node Quarantine</div>
                <div className="text-[11px] text-slate-400">
                  Allow IMMUNE-NET to dispatch cryptographic containment antibodies on Critical priority incidents.
                </div>
              </div>
              <button
                onClick={() => setAutoQuarantine(!autoQuarantine)}
                className={`w-11 h-6 rounded-full transition-colors relative ${
                  autoQuarantine ? 'bg-sky-600' : 'bg-slate-800'
                }`}
              >
                <div
                  className={`w-4 h-4 rounded-full bg-white transition-transform absolute top-1 ${
                    autoQuarantine ? 'left-6' : 'left-1'
                  }`}
                />
              </button>
            </div>
          </div>
        </div>

        {/* Integration Endpoints */}
        <div>
          <h3 className="text-xs font-bold text-white uppercase tracking-wider mb-2 flex items-center gap-2">
            <Database className="w-4 h-4 text-sky-400" />
            Backend Connection Endpoints
          </h3>
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3 font-mono text-xs">
            <div>
              <label className="block text-slate-400 text-2xs uppercase mb-1">FastAPI Core Ingress URL</label>
              <input
                type="text"
                defaultValue="http://localhost:8000"
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>

            <div>
              <label className="block text-slate-400 text-2xs uppercase mb-1">IBM Bob MCP Server Endpoint</label>
              <input
                type="text"
                defaultValue="http://localhost:8000/mcp"
                className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>
        </div>

        {/* Save Button */}
        <div className="pt-2 flex justify-end">
          <button
            onClick={handleSave}
            className="px-4 py-2 rounded bg-sky-600 hover:bg-sky-500 text-white font-bold text-xs flex items-center gap-2 transition-colors shadow-lg shadow-sky-600/20"
          >
            {saved ? <Check className="w-4 h-4" /> : <Save className="w-4 h-4" />}
            <span>{saved ? 'Settings Saved' : 'Save Calibration'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
