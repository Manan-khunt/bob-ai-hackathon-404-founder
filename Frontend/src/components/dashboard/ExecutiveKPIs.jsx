import React from 'react';
import { motion } from 'framer-motion';
import {
  Bell,
  GitMerge,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Radio,
  TrendingUp,
  TrendingDown,
} from 'lucide-react';
import { useAppStore } from '../../store';
import AnimatedCounter from '../common/AnimatedCounter';
import { fadeInUp, staggerContainer } from '../../utils/motion';

export default function ExecutiveKPIs() {
  const metrics = useAppStore((s) => s.metrics);

  const cards = [
    {
      id: 'alerts',
      label: 'TOTAL ALERTS',
      rawValue: metrics.totalAlerts,
      change: '+142/hr',
      trend: 'up',
      detail: 'Normalized across 8 telemetry feeds',
      icon: Bell,
      color: 'text-sky-400',
      border: 'border-slate-800/90',
      sparkline: 'M0,18 L10,15 L20,16 L30,12 L40,14 L50,9 L60,11 L70,6 L80,4',
      sparkColor: '#38BDF8',
    },
    {
      id: 'correlated',
      label: 'CORRELATED INCIDENTS',
      rawValue: metrics.correlatedIncidents,
      change: '96.2% Conf',
      trend: 'up',
      detail: 'Cross-source time & asset graph',
      icon: GitMerge,
      color: 'text-indigo-400',
      border: 'border-slate-800/90',
      sparkline: 'M0,16 L12,14 L24,15 L36,10 L48,11 L60,7 L72,8 L80,5',
      sparkColor: '#818CF8',
    },
    {
      id: 'threats',
      label: 'TRUE THREATS',
      rawValue: metrics.trueThreats,
      change: '+4 in last 24h',
      trend: 'up',
      detail: 'Corroborated by ≥ 2 sensors',
      icon: ShieldAlert,
      color: 'text-rose-400',
      border: 'border-rose-900/40 bg-rose-950/10',
      sparkline: 'M0,19 L15,18 L30,16 L45,12 L60,8 L70,6 L80,3',
      sparkColor: '#FB7185',
    },
    {
      id: 'fps',
      label: 'FALSE POSITIVES',
      rawValue: metrics.falsePositives,
      change: '91.4% Suppressed',
      trend: 'down',
      detail: 'Auto-triaged by AI rulebase',
      icon: CheckCircle2,
      color: 'text-emerald-400',
      border: 'border-emerald-900/40 bg-emerald-950/10',
      sparkline: 'M0,4 L12,7 L24,9 L36,12 L48,14 L60,15 L72,17 L80,18',
      sparkColor: '#34D399',
    },
    {
      id: 'critical',
      label: 'CRITICAL INCIDENTS',
      rawValue: metrics.criticalIncidents,
      change: 'Requires Action',
      trend: 'up',
      detail: 'Direct threat to command assets',
      icon: AlertTriangle,
      color: 'text-rose-400',
      border: 'border-rose-600/40 bg-rose-950/20 shadow-sm shadow-rose-950/40',
      highlight: true,
      sparkline: 'M0,16 L15,16 L30,14 L45,14 L60,10 L70,6 L80,4',
      sparkColor: '#F43F5E',
    },
    {
      id: 'sources',
      label: 'ACTIVE SOURCES',
      rawValue: metrics.activeSources,
      change: '100% Health',
      trend: 'up',
      detail: 'SIEM, Sat, Cyber, Intel, EDR, Net...',
      icon: Radio,
      color: 'text-cyan-400',
      border: 'border-slate-800/90',
      sparkline: 'M0,12 L10,12 L20,12 L30,12 L40,12 L50,12 L60,12 L70,12 L80,12',
      sparkColor: '#22D3EE',
    },
  ];

  return (
    <motion.div
      variants={staggerContainer(0.06, 0.05)}
      initial="hidden"
      animate="show"
      className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3 select-none"
    >
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <motion.div
            key={card.id}
            variants={fadeInUp}
            whileHover={{ y: -2, scale: 1.012 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            className={`p-3.5 rounded-lg bg-slate-900/95 border ${card.border} transition-shadow hover:shadow-lg hover:shadow-black/40 flex flex-col justify-between relative overflow-hidden group`}
          >
            {/* Top Row */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-2xs font-bold text-slate-400 tracking-wider">
                  {card.label}
                </span>
                <Icon className={`w-4 h-4 ${card.color} transition-transform group-hover:scale-110`} />
              </div>

              <div className="flex items-baseline justify-between">
                <div className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-1.5">
                  <AnimatedCounter value={card.rawValue} duration={850} />
                  {card.highlight && (
                    <span className="inline-flex relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75" />
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500" />
                    </span>
                  )}
                </div>

                {/* Subtle Micro Sparkline */}
                <div className="w-16 h-5 opacity-60 group-hover:opacity-100 transition-opacity">
                  <svg viewBox="0 0 80 20" className="w-full h-full overflow-visible">
                    <path
                      d={card.sparkline}
                      fill="none"
                      stroke={card.sparkColor}
                      strokeWidth="1.8"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                </div>
              </div>
            </div>

            {/* Bottom Row */}
            <div className="mt-2.5 pt-2 border-t border-slate-800/70">
              <div className="flex items-center justify-between text-2xs mb-0.5">
                <span
                  className={`font-semibold flex items-center gap-0.5 ${
                    card.id === 'fps' ? 'text-emerald-400' : card.color
                  }`}
                >
                  {card.trend === 'up' ? (
                    <TrendingUp className="w-3 h-3" />
                  ) : (
                    <TrendingDown className="w-3 h-3" />
                  )}
                  {card.change}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 truncate leading-snug">
                {card.detail}
              </p>
            </div>
          </motion.div>
        );
      })}
    </motion.div>
  );
}
