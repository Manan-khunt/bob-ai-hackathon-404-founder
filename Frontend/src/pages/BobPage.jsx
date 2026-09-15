import BobChat from '../components/BobChat';
import IbmTechPanel from '../components/IbmTechPanel';

export default function BobPage() {
  return (
    <div className="space-y-4">
      <div className="hacker-panel p-4 flex items-center justify-between">
        <span className="hacker-title text-sm">&gt; BOB // IBM WATSONX MCP CONSOLE</span>
        <span className="font-mono text-hacker-muted text-[10px]">JSON-RPC 2.0 over HTTP</span>
      </div>
      <BobChat />
      <IbmTechPanel />
    </div>
  );
}