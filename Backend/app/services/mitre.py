from typing import List, Dict, Optional


MITRE_TECHNIQUES: Dict[str, dict] = {
    "T1046": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "T1071": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1003": {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1210": {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "T1021": {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    "T1053": {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Execution"},
    "T1059": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1078": {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"},
    "T1110": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    "T1566": {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    "T1048": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1572": {"id": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control"},
    "T1090": {"id": "T1090", "name": "Proxy", "tactic": "Command and Control"},
    "T1105": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1486": {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1489": {"id": "T1489", "name": "Service Stop", "tactic": "Impact"},
    "T1490": {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1027": {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1055": {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
    "T1547": {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1498": {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    "T1190": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1189": {"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"},
    "T1082": {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1049": {"id": "T1049", "name": "System Network Connections Discovery", "tactic": "Discovery"},
    "T1018": {"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery"},
    "T1070": {"id": "T1070", "name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1562": {"id": "T1562", "name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1484": {"id": "T1484", "name": "Domain Policy Modification", "tactic": "Defense Evasion"},
}

EVENT_TYPE_TO_MITRE: Dict[str, List[str]] = {
    "Network Discovery (Port Scan)": ["T1046"],
    "Network DoS (SYN Flood)": ["T1498"],
    "Credential Attack (Brute Force)": ["T1110"],
    "Command and Control (Beacon)": ["T1071", "T1572"],
    "Lateral Movement Detected": ["T1210", "T1021"],
    "Data Exfiltration": ["T1048"],
    "Privilege Escalation": ["T1055"],
    "Malware Detected": ["T1059", "T1027"],
    "Ransomware Activity": ["T1486", "T1490", "T1489"],
    "Phishing Attempt": ["T1566"],
    "DNS Tunneling": ["T1572", "T1071"],
    "Credential Dump (Mimikatz-like)": ["T1003", "T1055"],
    "Suspicious PowerShell Execution": ["T1059", "T1055"],
    "Suspicious Outbound Connection": ["T1071", "T1090"],
    "SQL Injection Attempt": ["T1190"],
    "Cross-Site Scripting": ["T1189"],
}

SEVERITY_TO_CONFIDENCE = {
    "critical": 0.95,
    "high": 0.80,
    "medium": 0.55,
    "low": 0.25,
}


def map_event_to_mitre(event_type: str, additional_context: Optional[dict] = None) -> List[dict]:
    direct_match = EVENT_TYPE_TO_MITRE.get(event_type, [])
    if direct_match:
        return [MITRE_TECHNIQUES[tid].copy() for tid in direct_match if tid in MITRE_TECHNIQUES]

    event_lower = event_type.lower()
    fuzzy_matches = []
    for pattern, tids in EVENT_TYPE_TO_MITRE.items():
        pattern_words = pattern.lower().split()
        if any(w in event_lower for w in pattern_words):
            for tid in tids:
                if tid in MITRE_TECHNIQUES and MITRE_TECHNIQUES[tid] not in fuzzy_matches:
                    fuzzy_matches.append(MITRE_TECHNIQUES[tid].copy())
    if fuzzy_matches:
        return fuzzy_matches

    if additional_context:
        context_str = str(additional_context).lower()
        context_matches = []
        for pattern, tids in EVENT_TYPE_TO_MITRE.items():
            pattern_words = pattern.lower().split()
            if any(w in context_str for w in pattern_words):
                for tid in tids:
                    if tid in MITRE_TECHNIQUES and MITRE_TECHNIQUES[tid] not in context_matches:
                        context_matches.append(MITRE_TECHNIQUES[tid].copy())
        if context_matches:
            return context_matches

    return []


def get_technique(technique_id: str) -> Optional[dict]:
    return MITRE_TECHNIQUES.get(technique_id)


def get_all_techniques() -> List[dict]:
    return list(MITRE_TECHNIQUES.values())
