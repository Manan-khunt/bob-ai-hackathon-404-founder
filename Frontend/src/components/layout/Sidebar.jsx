import React from 'react';
import { NavLink } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  LayoutDashboard,
  BellRing,
  AlertOctagon,
  ShieldAlert,
  FileSpreadsheet,
  Radio,
  Bot,
  Settings,
  Layers,
} from 'lucide-react';
import { useAppStore } from '../../store';

const NAV_ITEMS = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/alerts', label: 'Alerts', icon: BellRing, badge: '1,284' },
  { to: '/incidents', label: 'Incidents', icon: AlertOctagon, badge: '6 Crit' },
  { to: '/mitre', label: 'MITRE ATT&CK', icon: ShieldAlert },
  { to: '/bluf', label: 'Commander BLUF', icon: FileSpreadsheet },
  { to: '/sources', label: 'Sources', icon: Radio, badge: '8 Live' },
  { to: '/bob', label: 'Bob AI', icon: Bot, isSpecial: true },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export default function Sidebar() {
  const operationalStatus = useAppStore((s) => s.operationalStatus);
  const backendConnected = useAppStore((s) => s.backendConnected);

  return (
    <motion.aside
      initial={{ opacity: 0, x: -16 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.35, ease: 'easeOut' }}
      className="w-64 bg-slate-950 border-r border-slate-800/80 flex flex-col justify-between shrink-0 h-screen sticky top-0 select-none z-30"
    >
      {/* Top Brand Header */}
      <div>
        <div className="h-16 flex items-center px-4 border-b border-slate-800/80 gap-3">
          <motion.div
            whileHover={{ scale: 1.05, rotate: 3 }}
            className="w-9 h-9 rounded-lg bg-gradient-to-br from-sky-500 to-blue-700 flex items-center justify-center shadow-lg shadow-sky-500/20 text-white shrink-0 cursor-pointer"
          >
            <Layers className="w-5 h-5" />
          </motion.div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className="font-extrabold text-sm tracking-wider text-white">IMMUNE-NET</span>
              <span className="text-[9px] uppercase px-1.5 py-0.5 rounded font-mono font-bold bg-sky-500/20 text-sky-400 border border-sky-500/30">
                v2.4
              </span>
            </div>
            <div className="text-[11px] text-slate-400 truncate tracking-tight">
              Command Intelligence
            </div>
          </div>
        </div>

        {/* Navigation links with animated active pill */}
        <nav className="p-3 space-y-1">
          <div className="px-3 py-1.5 text-2xs font-semibold uppercase tracking-wider text-slate-400">
            Operations &amp; Intelligence
          </div>

          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className="relative block"
              >
                {({ isActive }) => (
                  <div
                    className={`flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-colors relative z-10 ${
                      isActive
                        ? 'text-sky-200 font-semibold'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                    }`}
                  >
                    {/* Active Sliding Indicator using layoutId */}
                    {isActive && (
                      <motion.div
                        layoutId="activeNavIndicator"
                        className="absolute inset-0 rounded-md bg-sky-500/15 border border-sky-500/40 shadow-sm -z-10"
                        transition={{ type: 'spring', stiffness: 450, damping: 35 }}
                      />
                    )}

                    <div className="flex items-center gap-3">
                      <Icon className={`w-4 h-4 ${isActive || item.isSpecial ? 'text-sky-400' : 'text-slate-400'}`} />
                      <span>{item.label}</span>
                    </div>

                    {item.badge && (
                      <span
                        className={`text-2xs px-1.5 py-0.5 rounded font-mono font-medium ${
                          item.badge.includes('Crit')
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : 'bg-slate-800/80 text-slate-400 border border-slate-700/60'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                  </div>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Bottom Operational Status Bar */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/90 text-2xs space-y-2">
        <div className="flex items-center justify-between px-1">
          <span className="text-slate-400 uppercase tracking-wider font-semibold">System Status</span>
          <span className="flex items-center gap-1.5 font-medium text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            OPERATIONAL
          </span>
        </div>

        <div className="flex items-center justify-between px-1">
          <span className="text-slate-400 uppercase tracking-wider font-semibold">Data Stream</span>
          <span className="text-slate-300 font-mono">
            {backendConnected ? 'FASTAPI LIVE' : 'SYNTHETIC FUSION'}
          </span>
        </div>

        <div className="flex items-center justify-between px-1">
          <span className="text-slate-400 uppercase tracking-wider font-semibold">Threat State</span>
          <span
            className={`font-semibold px-1.5 py-0.5 rounded text-[10px] transition-colors ${
              operationalStatus === 'CRITICAL'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 animate-pulse'
                : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
            }`}
          >
            {operationalStatus}
          </span>
        </div>

        <div className="pt-2 text-[10px] text-slate-400 text-center border-t border-slate-900 font-mono">
          DEFENCE ENCLAVE // LEVEL 4 AUTHORIZED
        </div>
      </div>
    </motion.aside>
  );
}
