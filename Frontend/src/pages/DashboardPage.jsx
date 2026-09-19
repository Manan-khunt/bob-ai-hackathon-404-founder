import React from 'react';
import { motion } from 'framer-motion';
import ExecutiveKPIs from '../components/dashboard/ExecutiveKPIs';
import PrioritizedThreatsTable from '../components/dashboard/PrioritizedThreatsTable';
import MultiSourceAlertFeed from '../components/dashboard/MultiSourceAlertFeed';
import TriageFunnelPanel from '../components/dashboard/TriageFunnelPanel';
import SourceCorrelationGraph from '../components/dashboard/SourceCorrelationGraph';
import MitreAttackPanel from '../components/dashboard/MitreAttackPanel';
import CommanderBlufCard from '../components/dashboard/CommanderBlufCard';
import CommanderTimeline from '../components/dashboard/CommanderTimeline';
import IntelligenceSourcesPanel from '../components/dashboard/IntelligenceSourcesPanel';

export default function DashboardPage() {
  return (
    <div className="space-y-6 max-w-[1700px] mx-auto pb-12">
      {/* 4. KPI cards stagger in (100-350ms) */}
      <motion.section
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.1 }}
      >
        <ExecutiveKPIs />
      </motion.section>

      {/* 9. Commander BLUF reveals with emphasis */}
      <motion.section
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45, delay: 0.22 }}
      >
        <CommanderBlufCard />
      </motion.section>

      {/* 5 & 7. Priority Table & Source Correlation Graph */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <motion.div
          className="xl:col-span-2"
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.38, delay: 0.3 }}
        >
          <PrioritizedThreatsTable />
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.42, delay: 0.38 }}
        >
          <SourceCorrelationGraph />
        </motion.div>
      </div>

      {/* Triage Funnel & MITRE Attack Panel */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.38, delay: 0.45 }}
        >
          <TriageFunnelPanel />
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.38, delay: 0.52 }}
        >
          <MitreAttackPanel />
        </motion.div>
      </div>

      {/* 6. Multi-Source Alert Feed enters */}
      <motion.section
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, delay: 0.58 }}
      >
        <MultiSourceAlertFeed limit={8} />
      </motion.section>

      {/* 8. Timeline & Ingestion Sources */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.38, delay: 0.65 }}
        >
          <CommanderTimeline />
        </motion.div>
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.38, delay: 0.72 }}
        >
          <IntelligenceSourcesPanel />
        </motion.div>
      </div>
    </div>
  );
}
