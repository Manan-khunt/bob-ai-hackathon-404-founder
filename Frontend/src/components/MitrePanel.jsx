import { useState } from 'react';
import { useStore } from '../store';
import { formatConf, confColor } from '../lib/format';

const TECH_DESCRIPTIONS = {
  T1496: { tactic: 'Impact / Resource Hijacking', desc: 'Abuses compute resources of a victim system for resource-intensive activities, e.g. cryptomining.' },
  T1071: { tactic: 'Command & Control', desc: 'Uses standard application-layer protocols over existing ports to communicate with C2.' },
  T1210: { tactic: 'Lateral Movement', desc: 'Exploits software vulnerabilities to gain access to adjacent systems over a network.' },
  T1059: { tactic: 'Execution', desc: 'Executes arbitrary commands or payloads through a command-and-scripting interpreter.' },
  T1056: { tactic: 'Credential Access', desc: 'Captures credentials by hooking input or keylogging.' },
  T1203: { tactic: 'Execution', desc: 'Exploits a vulnerability in a client application to execute code on it.' },
  T1486: { tactic: 'Impact', desc: 'Encrypts victim data and demands payment for decryption keys.' },
  T1041: { tactic: 'Exfiltration', desc: 'Exfiltrates data over the primary command and control channel.' },
  T1027: { tactic: 'Defense Evasion', desc: 'Obfuscates data, files, or indicators to avoid detection.' },
  T1078: { tactic: 'Defense Evasion', desc: 'Abuses valid accounts to gain access and avoid detection.' },
  T1114: { tactic: 'Collection', desc: 'Collects email accounts and data.' },
  T1560: { tactic: 'Collection', desc: 'Archives and collects data in a location for exfiltration.' },
  T1046: { tactic: 'Discovery', desc: 'Scans target hosts for open network ports and services.' },
};

const KNOWN = {
  cryptominer: { t: 'T1496', k: 'Resource Hijacking' },
  port_scan: { t: 'T1046', k: 'Network Service Scanning' },
  c2_beacon: { t: 'T1071', k: 'Application Layer Protocol' },
  worm: { t: 'T1210', k: 'Exploitation of Remote Services' },
};

export default function MitrePanel() {
  const incidents = useStore(s => s.incidents);
  const [open, setOpen] = useState(null);

  const rows = incidents.slice(0, 12).map(inc => {
    const mitre = inc.mitre || {};
    let tid = mitre.technique_id;
    let name = mitre.technique_name;
    if (!tid || tid === 'UNKNOWN') {
      const known = KNOWN[inc.scenario || inc.attack_type];
      if (known) { tid = known.t; name = known.k; }
    }
    return {
      id: inc.incident_id,
      tid: tid || 'UNKNOWN',
      name: name || 'Unclassified',
      confidence: inc.confidence != null ? inc.confidence * 100 : (inc.confidence_score || 0) * 100,
      tactic: mitre.tactic || TECH_DESCRIPTIONS[tid]?.tactic || 'Unknown',
      desc: TECH_DESCRIPTIONS[tid]?.desc || 'No description in MITRE cache.',
      node: inc.node_id,
      ts: inc.timestamp,
    };
  });

  if (!rows.length) {
    return (
      <div className="hacker-panel p-4">
        <div className="hacker-title text-sm mb-2">&gt; MITRE ATT&CK // DETECTED TECHNIQUES</div>
        <div className="font-mono text-hacker-muted text-[11px]">no incident telemetry yet // waiting for signal...</div>
      </div>
    );
  }

  return (
    <div className="hacker-panel p-4">
      <div className="hacker-title text-sm mb-3">&gt; MITRE ATT&CK // DETECTED TECHNIQUES</div>
      <div className="space-y-1">
        {rows.map((r, i) => {
          const expanded = open === r.id;
          return (
            <div key={r.id} className="border border-hacker-border rounded-hard hover:bg-hacker-border/30 transition-colors">
              <button
                className="w-full grid grid-cols-[70px_1fr_80px_70px] items-center gap-2 px-3 py-2 cursor-pointer"
                onClick={() => setOpen(expanded ? null : r.id)}
              >
                <span className="font-mono text-hacker-blue text-[11px] text-left">{r.tid}</span>
                <span className="font-mono text-hacker-white text-[12px] text-center truncate">{r.name}</span>
                <span className="conf-bar w-full"><span className={confColor(r.confidence)} style={{ width: `${Math.min(100, r.confidence)}%` }} /></span>
                <span className="font-mono text-hacker-muted text-[10px] text-right">{formatConf(r.confidence)}</span>
              </button>
              {expanded && (
                <div className="px-3 pb-3 font-mono text-[11px] text-hacker-white/80 border-t border-hacker-border/50 pt-2">
                  <div className="text-hacker-amber">TACTIC: {r.tactic}</div>
                  <div className="text-hacker-muted mt-1">{r.desc}</div>
                  <div className="text-hacker-blue mt-1">SOURCE: {r.node} @ {r.ts}</div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}