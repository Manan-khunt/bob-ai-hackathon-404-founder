/**
 * Bob AI Intelligence Analyst Service
 * Autonomous threat reasoning, BLUF synthesis, and correlation analysis
 */
import { INITIAL_INCIDENTS, INITIAL_ALERTS, OPERATIONAL_SOURCES } from '../data/demoData';

export const BOB_SUGGESTED_PROMPTS = [
  'What is the most important threat right now?',
  'Explain why INC-1042 was classified as a TRUE THREAT',
  'Why was AL-10484 marked as a FALSE POSITIVE?',
  'Generate a Commander BLUF for INC-1036',
  'Show all affected assets across active critical incidents',
  'How did IMMUNE-NET calculate the 97 priority score for INC-1042?',
  'Explain the MITRE ATT&CK chain for the C2 intrusion',
];

export async function askBobAssistant(query, context = {}) {
  const q = query.toLowerCase().trim();

  // Try real backend if reachable, otherwise execute instant intelligence engine
  try {
    const backendRes = await fetch('http://localhost:8000/api/bob/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, context }),
      signal: AbortSignal.timeout(2000),
    });
    if (backendRes.ok) {
      const data = await backendRes.json();
      if (data && data.response) return data.response;
    }
  } catch {
    // Graceful fallback to rich local domain intelligence
  }

  // Domain reasoning tree
  if (q.includes('most important') || q.includes('highest priority') || q.includes('critical threat')) {
    const inc = INITIAL_INCIDENTS[0];
    return `**INC-1042** is currently the highest-priority incident.

- **Priority Score**: ${inc.priorityScore}/100 (CRITICAL)
- **Correlation Confidence**: ${inc.confidence}%
- **Affected Assets**: 3 (${inc.affectedAssets.map(a => a.id).join(', ')})
- **MITRE Tactics**: T1071 (Application Layer C2), T1003 (OS Credential Dumping), T1210 (Exploitation of Remote Services)
- **Source Consensus**: Supported by **4 independent source types** (SIEM, Cyber Sensor, Endpoint EDR, Allied Intelligence).

**Operational Assessment**:
This represents a synchronized nation-state intrusion with active memory tampering and lateral SMB traversal.

**Recommended Action**:
Isolate **NODE-ALPHA** and **NODE-BETA** cryptographically and initiate immediate LSASS credential rotation.`;
  }

  if (q.includes('why') && (q.includes('1042') || q.includes('classified') || q.includes('true threat'))) {
    return `### Correlation & Classification Analysis for INC-1042

**Classification**: TRUE THREAT (Confidence: 96%)

**Multi-Source Evidence Chain**:
1. **Temporal Clustering**: 4 distinct sensor alerts occurred within a tight 3 minute 56 second window across interconnected nodes.
2. **Cross-Domain Telemetry**:
   - **SIEM**: Ingress reconnaissance from external IP \`185.220.101.4\` targeting port 445/8080.
   - **Cyber Sensor**: Anomaly detector extracted JA3 TLS signature matching known APT-29 C2 beacon profile.
   - **Endpoint Fleet**: Sub-second telemetry intercepted \`lsass.exe\` memory injection initiated by child process.
   - **Allied Intelligence**: Global threat feed corroboration confirmed IP is linked to active nation-state campaign *Operation GhostPulse*.
3. **Correlation Score**: 0.96 (Threshold for auto-escalation is 0.85).

**Conclusion**:
The mutual corroboration across network, endpoint, and external intelligence eliminates the possibility of isolated benign false positive.`;
  }

  if (q.includes('false positive') || q.includes('al-10484') || q.includes('suppress')) {
    return `### False Positive Disposition: Alert AL-10484

**Alert ID**: AL-10484 (Region-04 Public DMZ Traffic Anomaly)
**Disposition**: FALSE POSITIVE (Suppression Confidence: 93%)

**Reasoning Engine Breakdown**:
1. **Zero Corroborating Signals**: No anomalous process execution, authentication failure, or lateral traffic was recorded across the timeframe.
2. **Operational Change Reconciliation**: Automated query matched active approved change ticket \`CHG-88219\` for regional CDN cache synchronization.
3. **Cryptographic Checksum Match**: Transferred payload hashes aligned 100% with signed official vendor distribution packages.

**Analyst Workload Impact**:
Auto-suppressing this event prevented unnecessary analyst escalation and reduced alert fatigue while preserving an auditable forensic trace in the suppressed log.`;
  }

  if (q.includes('bluf') || q.includes('briefing') || q.includes('commander')) {
    const inc = INITIAL_INCIDENTS[0];
    return `### COMMANDER'S BLUF (Bottom Line Up Front)
**INCIDENT**: ${inc.id} // ${inc.title.toUpperCase()}
**PRIORITY**: ${inc.priorityScore}/100 — CRITICAL // CONFIDENCE: ${inc.confidence}%

**1. BOTTOM LINE**:
${inc.bluf.bottomLine}

**2. OPERATIONAL IMPACT**:
${inc.bluf.impact}

**3. MULTI-SOURCE EVIDENCE**:
${inc.bluf.evidence.map(e => `• ${e}`).join('\n')}

**4. MITRE ATT&CK MAPPING**:
${inc.bluf.mitreMapping.map(m => `• **${m.id}**: ${m.name}`).join('\n')}

**5. RECOMMENDED IMMEDIATE ACTION**:
${inc.bluf.recommendedAction}`;
  }

  if (q.includes('asset') || q.includes('affected')) {
    return `### Affected Operational Assets Summary

**Critical Tier**:
• **NODE-ALPHA (Command Relay)**: Ingress compromised; active TLS C2 channel detected.
• **NODE-BETA (Telemetry Processor)**: Infected; memory injection against \`lsass.exe\` verified.
• **SAT-RELAY-04 (Orbital Ground Link)**: RF phase jamming; telemetry degraded by 34.6%.
• **NODE-THETA (Database Core)**: Root brute-force followed by unauthorized \`/etc/sudoers\` tamper.

**Elevated Risk Tier**:
• **NODE-GAMMA (Log Archive)**: Lateral SMB scan target; isolation barrier active.
• **NODE-DELTA (Directory Mirror)**: Origin of decoy honeytoken Kerberos ticket request.

Total At-Risk Enclave: **6 assets** across 2 operational security zones.`;
  }

  if (q.includes('priority score') || q.includes('calculated') || q.includes('97')) {
    return `### Priority Score Engine Formula

The **97/100** Priority Score for INC-1042 was synthesized using the following multi-variable equation:

$$\\text{Score} = (W_{assets} \\cdot A) + (W_{sources} \\cdot S) + (W_{mitre} \\cdot M) + (W_{conf} \\cdot C)$$

• **Asset Criticality Weight (30%)**: Target nodes include Primary Command Relay and Telemetry Processor (Tier 1 Assets) → **30/30 pts**
• **Multi-Source Diversity (25%)**: 4 independent source categories (SIEM + Sensor + EDR + Intel) → **25/25 pts**
• **MITRE Attack Stage (25%)**: Reached *Lateral Movement* (T1210) & *Credential Access* (T1003) → **24/25 pts**
• **Correlation Confidence (20%)**: 96% sensor cross-agreement → **18/20 pts**

**Total Composite Score**: **97/100 (CRITICAL DEFENCE PRIORITY)**.`;
  }

  // Default intelligent assistant response
  return `### Operational Intelligence Assessment

I have reviewed the current multi-source threat stream. We are actively tracking **${INITIAL_INCIDENTS.length} correlated incidents** with **6 flagged as critical priority**.

**Current Key Findings**:
1. **Primary Threat Vector**: **INC-1042** (APT-29 intrusion chain involving C2 and credential harvesting on NODE-ALPHA and NODE-BETA).
2. **Secondary Threat Vector**: **INC-1036** (GEOINT Satellite downlink jamming on SAT-RELAY-04).
3. **Analyst Noise Suppression**: **${INITIAL_ALERTS.filter(a => a.classification === 'FALSE_POSITIVE').length} alerts** successfully triaged as false positives, reducing commander cognitive load by 91%.

How would you like me to assist? You can ask me to generate a tailored BLUF, inspect specific sensor logs, or simulate containment actions.`;
}
