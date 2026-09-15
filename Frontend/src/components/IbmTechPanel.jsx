const IBM_COMPONENTS = [
  {
    name: 'IBM watsonx.ai',
    role: 'Generates commander-level threat briefings',
    desc: 'Enterprise AI platform that converts structured detection evidence into concise, executive-ready natural-language intelligence.',
    tag: 'LLM PLATFORM',
    color: '#0F62FE',
  },
  {
    name: 'Granite',
    role: 'Threat evidence → natural-language intelligence',
    desc: 'Open-weights IBM foundation model (ibm/granite-3-8b-instruct) that summarizes detection facts into a 3-sentence BLUF briefing.',
    tag: 'FOUNDATION MODEL',
    color: '#FFB300',
  },
  {
    name: 'IBM Bob',
    role: 'Agentic SOC analyst',
    desc: 'AI assistant front-end that drives the platform through intent-based commands and natural-language interaction.',
    tag: 'ASSISTANT',
    color: '#00FF41',
  },
  {
    name: 'MCP',
    role: 'Model Context Protocol integration',
    desc: 'Tool server (JSON-RPC 2.0 over HTTP) exposing fleet status, incidents, antibodies, blast radius and simulation to Bob.',
    tag: 'PROTOCOL',
    color: '#00B4D8',
  },
];

export default function IbmTechPanel() {
  return (
    <div className="hacker-panel p-4">
      <div className="hacker-title text-sm mb-3">&gt; IBM TECHNOLOGY // INTEGRATION MAP</div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {IBM_COMPONENTS.map(c => (
          <div key={c.name} className="bg-hacker-panel border border-hacker-border rounded-hard p-3">
            <div className="flex items-center justify-between mb-1">
              <span className="font-orbitron font-bold text-[12px]" style={{ color: c.color }}>{c.name}</span>
              <span className="font-mono text-[9px] px-1.5 py-0.5 rounded-hard" style={{ backgroundColor: `${c.color}22`, color: c.color }}>{c.tag}</span>
            </div>
            <div className="font-mono text-hacker-white text-[11px]">→ {c.role}</div>
            <div className="font-mono text-hacker-muted text-[10px] mt-1 leading-4">{c.desc}</div>
          </div>
        ))}
      </div>
      <div className="font-mono text-hacker-muted text-[10px] mt-3">
        Watsonx is optional: when no credentials are configured, the system automatically uses the deterministic rule-based BLUF generator — the demo never breaks.
      </div>
    </div>
  );
}