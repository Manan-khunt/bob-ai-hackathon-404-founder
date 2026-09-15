import NodeMesh from '../components/NodeMesh';
import Timeline from '../components/Timeline';
import BlastRadiusMap from '../components/BlastRadiusMap';
import MitrePanel from '../components/MitrePanel';
import AptFingerprint from '../components/AptFingerprint';
import BlufFeed from '../components/BlufFeed';
import HerdImmunityStats from '../components/HerdImmunityStats';

export default function Dashboard() {
  return (
    <div className="space-y-4">
      <HerdImmunityStats />
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">
          <NodeMesh />
          <BlastRadiusMap />
        </div>
        <Timeline />
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <MitrePanel />
        <AptFingerprint />
        <BlufFeed limit={6} />
      </div>
    </div>
  );
}