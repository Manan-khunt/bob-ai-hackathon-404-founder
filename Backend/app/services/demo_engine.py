from typing import List, Dict, Optional
from datetime import datetime, timezone, timedelta
import random
import string

from .normalization import normalize_alert
from .correlation import CorrelationEngine
from .triage import triage_event, classify_confidence
from .prioritization import compute_priority_score, priority_level, priority_rank
from .mitre import map_event_to_mitre, MITRE_TECHNIQUES
from .bluf import generate_bluf


def _gen_id(prefix: str) -> str:
    return f"{prefix}-{''.join(random.choices(string.ascii_uppercase + string.digits, k=5))}"


CORRELATED_INCIDENTS = [
    {
        "id": "INC-1042",
        "title": "Coordinated Cross-Domain C2 & Lateral Memory Injection",
        "threatType": "Nation-State Advanced Persistent Threat",
        "severity": "CRITICAL",
        "status": "ACTIVE INVESTIGATION",
        "mitreIds": ["T1071", "T1003", "T1210", "T1046"],
        "mitreTechnique": "Application Layer Protocol & Memory Injection",
        "sources": ["SIEM", "CYBER SENSOR", "ENDPOINT", "INTELLIGENCE"],
        "affectedAssets": [
            {"asset": "DC-PRIMARY", "status": "CRITICAL", "type": "Domain Controller"},
            {"asset": "FILE-SERVER-01", "status": "COMPROMISED", "type": "File Server"},
            {"asset": "NODE-ALPHA", "status": "AT RISK", "type": "Command Relay"},
        ],
        "summary": "Multi-stage intrusion with initial access via phishing, lateral movement via SMB exploitation, credential dumping with Mimikatz, and C2 over HTTPS.",
        "attribution": "APT-37 (Reaper)",
    },
    {
        "id": "INC-1043",
        "title": "Automated Ransomware Deployment via RDP Brute Force",
        "threatType": "Cybercrime Ransomware",
        "severity": "HIGH",
        "status": "ACTIVE INVESTIGATION",
        "mitreIds": ["T1110", "T1021", "T1486"],
        "mitreTechnique": "Brute Force, Remote Services, Data Encrypted for Impact",
        "sources": ["SIEM", "ENDPOINT", "HONEYPOT"],
        "affectedAssets": [
            {"asset": "FILE-SERVER-02", "status": "COMPROMISED", "type": "File Server"},
            {"asset": "BACKUP-01", "status": "AT RISK", "type": "Backup Server"},
        ],
        "summary": "RDP brute force from external IP led to credential compromise and ransomware deployment.",
        "attribution": "LockBit Affiliate",
    },
    {
        "id": "INC-1044",
        "title": "DNS Tunneling Data Exfiltration Campaign",
        "threatType": "Advanced Persistent Threat",
        "severity": "HIGH",
        "status": "INVESTIGATING",
        "mitreIds": ["T1572", "T1048", "T1071"],
        "mitreTechnique": "Protocol Tunneling, Exfiltration Over Alternative Protocol",
        "sources": ["NETWORK_SENSOR", "SIEM", "INTELLIGENCE"],
        "affectedAssets": [
            {"asset": "DB-PRIMARY", "status": "HIGH RISK", "type": "Database Server"},
            {"asset": "WORKSTATION-042", "status": "AT RISK", "type": "Developer Workstation"},
        ],
        "summary": "DNS queries to suspicious domains indicate data exfiltration via DNS tunneling.",
        "attribution": "Unknown (Investigating)",
    },
]

ALL_DEMO_ALERTS = [
    {
        "id": "AL-10482",
        "source": "SIEM",
        "asset": "NODE-ALPHA",
        "asset_ip": "10.42.1.15",
        "event": "Port Reconnaissance & Rapid SYN Sequence",
        "normalized_event": "Network Discovery (Port Scan)",
        "severity": "Medium",
        "confidence": 82,
        "mitre": "T1046",
        "mitreName": "Network Service Discovery",
        "explanation": "Sequential SYN probes across 200+ ports within 2 seconds from external IP.",
        "incident_id": "INC-1042",
        "correlation_status": "CORRELATED",
        "classification": "TRUE_THREAT",
        "correlation_score": 0.85,
    },
    {
        "id": "AL-10483",
        "source": "CYBER_SENSOR",
        "asset": "DC-PRIMARY",
        "asset_ip": "10.42.0.10",
        "event": "Credential Dump via LSASS Memory Access",
        "normalized_event": "Credential Dump (Mimikatz-like)",
        "severity": "Critical",
        "confidence": 94,
        "mitre": "T1003",
        "mitreName": "OS Credential Dumping",
        "explanation": "LSASS.exe memory accessed by unknown process. Mimikatz signature detected.",
        "incident_id": "INC-1042",
        "correlation_status": "CORRELATED",
        "classification": "TRUE_THREAT",
        "correlation_score": 0.96,
    },
    {
        "id": "AL-10484",
        "source": "ENDPOINT",
        "asset": "FILE-SERVER-01",
        "asset_ip": "10.42.2.20",
        "event": "Suspicious SMB Lateral Movement",
        "normalized_event": "Lateral Movement Detected",
        "severity": "High",
        "confidence": 88,
        "mitre": "T1210",
        "mitreName": "Exploitation of Remote Services",
        "explanation": "SMB connection from NODE-ALPHA to FILE-SERVER-01 with unusual user agent.",
        "incident_id": "INC-1042",
        "correlation_status": "CORRELATED",
        "classification": "TRUE_THREAT",
        "correlation_score": 0.91,
    },
    {
        "id": "AL-10485",
        "source": "INTELLIGENCE",
        "asset": "EXTERNAL-THREAT",
        "event": "APT-37 Infrastructure Correlation",
        "normalized_event": "Threat Intelligence Match",
        "severity": "High",
        "confidence": 78,
        "mitre": "T1071",
        "mitreName": "Application Layer Protocol",
        "explanation": "C2 infrastructure matches known APT-37 patterns across 3 threat feeds.",
        "incident_id": "INC-1042",
        "correlation_status": "CORRELATED",
        "classification": "TRUE_THREAT",
        "correlation_score": 0.88,
    },
    {
        "id": "AL-10486",
        "source": "NETWORK_SENSOR",
        "asset": "DB-PRIMARY",
        "asset_ip": "10.42.3.5",
        "event": "DNS Query Volume Anomaly - 47x baseline",
        "normalized_event": "Suspicious Outbound Connection",
        "severity": "High",
        "confidence": 85,
        "mitre": "T1572",
        "mitreName": "Protocol Tunneling",
        "explanation": "Massive spike in DNS TXT queries to suspicious domains indicating tunneling.",
        "incident_id": "INC-1044",
        "correlation_status": "CORRELATED",
        "classification": "TRUE_THREAT",
        "correlation_score": 0.82,
    },
    {
        "id": "AL-10487",
        "source": "SIEM",
        "asset": "WORKSTATION-042",
        "asset_ip": "10.42.5.42",
        "event": "Brute Force Authentication Attempts",
        "normalized_event": "Credential Attack (Brute Force)",
        "severity": "Medium",
        "confidence": 75,
        "mitre": "T1110",
        "mitreName": "Brute Force",
        "explanation": "347 failed login attempts from single source in 5 minutes.",
        "incident_id": "INC-1043",
        "correlation_status": "CORRELATED",
        "classification": "TRUE_THREAT",
        "correlation_score": 0.78,
    },
    {
        "id": "AL-10488",
        "source": "HONEYPOT",
        "asset": "HONEYPOT-DMZ",
        "asset_ip": "10.42.99.10",
        "event": "Advanced Persistent Honeypot Interaction",
        "normalized_event": "Honeypot Activity Detected",
        "severity": "High",
        "confidence": 92,
        "mitre": "T1021",
        "mitreName": "Remote Services",
        "explanation": "Multi-stage interaction with honeypot including credential harvesting tools.",
        "incident_id": "INC-1043",
        "correlation_status": "CORRELATED",
        "classification": "TRUE_THREAT",
        "correlation_score": 0.89,
    },
    {
        "id": "AL-10489",
        "source": "SIEM",
        "asset": "WEB-SERVER-03",
        "asset_ip": "10.42.4.30",
        "event": "Routine System Backup Completed",
        "normalized_event": "System Backup",
        "severity": "Low",
        "confidence": 95,
        "mitre": None,
        "mitreName": None,
        "explanation": "Scheduled backup completed successfully.",
        "incident_id": None,
        "correlation_status": "UNCORRELATED",
        "classification": "FALSE_POSITIVE",
        "correlation_score": 0.05,
    },
    {
        "id": "AL-10490",
        "source": "ENDPOINT",
        "asset": "HR-PC-12",
        "asset_ip": "10.42.10.12",
        "event": "Software Update Installed",
        "normalized_event": "Software Installation",
        "severity": "Low",
        "confidence": 99,
        "mitre": None,
        "mitreName": None,
        "explanation": "Approved software update installed via WSUS.",
        "incident_id": None,
        "correlation_status": "UNCORRELATED",
        "classification": "FALSE_POSITIVE",
        "correlation_score": 0.02,
    },
    {
        "id": "AL-10491",
        "source": "OSINT",
        "asset": "EXTERNAL-OSINT",
        "event": "Threat Feed Update - New IOCs",
        "normalized_event": "Intelligence Update",
        "severity": "Low",
        "confidence": 60,
        "mitre": None,
        "mitreName": None,
        "explanation": "Routine threat intelligence feed update with new indicators.",
        "incident_id": None,
        "correlation_status": "UNCORRELATED",
        "classification": "NEEDS_REVIEW",
        "correlation_score": 0.35,
    },
]


def get_demo_scenario(scenario_name: str) -> Dict:
    scenarios = {
        "coordinated_intrusion": _coordinated_intrusion,
        "benign_noise": _benign_noise,
        "c2_campaign": _c2_campaign,
        "lateral_movement": _lateral_movement,
        "mixed_alert_surge": _mixed_alert_surge,
    }
    scenario_fn = scenarios.get(scenario_name, _coordinated_intrusion)
    return scenario_fn()


def _build_incident_from_template(template: dict, alerts: list, priority_score: int, confidence: float) -> dict:
    sources_set = list(set(a.get("source", "Unknown") for a in alerts))
    mitre_ids = list(set(a.get("mitre") for a in alerts if a.get("mitre")))
    mitre_techniques = []
    for mid in mitre_ids:
        t = MITRE_TECHNIQUES.get(mid)
        if t:
            mitre_techniques.append(t)

    first_time = min((a.get("timestamp", "00:00:00") for a in alerts), default="00:00:00")
    last_time = max((a.get("timestamp", "00:00:00") for a in alerts), default="00:00:00")

    incident_data = {
        **template,
        "confidence": confidence,
        "priority_score": priority_score,
        "priority_level": priority_level(priority_score),
        "sources": sources_set,
        "source_count": len(sources_set),
        "alert_count": len(alerts),
        "mitre_ids": mitre_ids,
        "first_seen": first_time,
        "last_seen": last_time,
    }

    bluf = generate_bluf(incident_data, alerts, mitre_techniques)
    incident_data["bluf"] = bluf

    timeline = []
    for a in sorted(alerts, key=lambda x: x.get("timestamp", "")):
        timeline.append({
            "time": a.get("timestamp", "00:00:00"),
            "source": a.get("source", "Unknown"),
            "event": a.get("event", "Unknown"),
        })
    incident_data["timeline"] = timeline
    incident_data["priorityRank"] = priority_rank(priority_score)
    incident_data["mitreTechnique"] = template.get("mitreTechnique", "")
    incident_data["mitreIds"] = mitre_ids

    return incident_data


def _coordinated_intrusion() -> Dict:
    template = CORRELATED_INCIDENTS[0]
    alerts = [a for a in ALL_DEMO_ALERTS if a.get("incident_id") == "INC-1042"]
    priority_score = 97
    confidence = 0.96
    incident = _build_incident_from_template(template, alerts, priority_score, confidence)
    return {
        "scenario": "coordinated_intrusion",
        "alerts": alerts,
        "incidents": [incident],
    }


def _benign_noise() -> Dict:
    alerts = [a for a in ALL_DEMO_ALERTS if a.get("classification") == "FALSE_POSITIVE"]
    return {
        "scenario": "benign_noise",
        "alerts": alerts,
        "incidents": [],
    }


def _c2_campaign() -> Dict:
    c2_alerts = [
        a for a in ALL_DEMO_ALERTS
        if a.get("mitre") in ("T1071", "T1572", "T1090")
    ]
    if not c2_alerts:
        c2_alerts = [a for a in ALL_DEMO_ALERTS if a.get("classification") == "TRUE_THREAT"][:2]

    template = {
        **CORRELATED_INCIDENTS[2],
        "id": _gen_id("INC"),
        "title": "C2 Campaign - Encrypted Command Channel Detected",
    }
    priority_score = 88
    confidence = 0.90
    incident = _build_incident_from_template(template, c2_alerts, priority_score, confidence)
    return {
        "scenario": "c2_campaign",
        "alerts": c2_alerts,
        "incidents": [incident],
    }


def _lateral_movement() -> Dict:
    lateral_alerts = [
        a for a in ALL_DEMO_ALERTS
        if a.get("mitre") in ("T1210", "T1021", "T1003", "T1046")
    ]
    if not lateral_alerts:
        lateral_alerts = ALL_DEMO_ALERTS[:3]

    template = {
        **CORRELATED_INCIDENTS[0],
        "id": _gen_id("INC"),
        "title": "Lateral Movement - SMB Exploitation Chain",
    }
    priority_score = 91
    confidence = 0.93
    incident = _build_incident_from_template(template, lateral_alerts, priority_score, confidence)
    return {
        "scenario": "lateral_movement",
        "alerts": lateral_alerts,
        "incidents": [incident],
    }


def _mixed_alert_surge() -> Dict:
    alerts = ALL_DEMO_ALERTS.copy()

    incidents = []
    for template in CORRELATED_INCIDENTS:
        inc_alerts = [a for a in alerts if a.get("incident_id") == template.get("id")]
        if inc_alerts:
            ps = random.randint(75, 99)
            conf = round(random.uniform(0.80, 0.98), 2)
            inc = _build_incident_from_template(template, inc_alerts, ps, conf)
            incidents.append(inc)

    return {
        "scenario": "mixed_alert_surge",
        "alerts": alerts,
        "incidents": incidents,
    }
