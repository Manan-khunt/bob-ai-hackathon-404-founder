import AntibodyLibrary from '../components/AntibodyLibrary';
import ImmuneLifecycle from '../components/ImmuneLifecycle';

export default function Antibodies() {
  return (
    <div className="space-y-4">
      <div className="hacker-panel p-4">
        <span className="hacker-title text-sm">&gt; IMMUNE MEMORY // DIGITAL ANTIBODY STORE</span>
      </div>
      <AntibodyLibrary />
      <ImmuneLifecycle />
    </div>
  );
}