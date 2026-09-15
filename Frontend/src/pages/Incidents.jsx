import MitrePanel from '../components/MitrePanel';
import AptFingerprint from '../components/AptFingerprint';
import BlufFeed from '../components/BlufFeed';

export default function Incidents() {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <MitrePanel />
        <AptFingerprint />
      </div>
      <BlufFeed />
    </div>
  );
}