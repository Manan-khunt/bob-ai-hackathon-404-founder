import NodeMesh from '../components/NodeMesh';
import BlastRadiusMap from '../components/BlastRadiusMap';
import NodeDetailPanel from '../components/NodeDetailPanel';

export default function Nodes() {
  return (
    <div className="space-y-4">
      <div className="hacker-panel p-4 flex items-center justify-between">
        <span className="hacker-title text-sm">&gt; FLEET COMMAND // NODE OPS</span>
        <span className="font-mono text-hacker-muted text-[10px]">select node to open detail drawer</span>
      </div>
      <NodeMesh />
      <BlastRadiusMap />
      <NodeDetailPanel />
    </div>
  );
}