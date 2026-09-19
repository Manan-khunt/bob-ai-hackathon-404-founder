import json
import re
from typing import Optional
from datetime import datetime, timezone


FIELD_ALIASES = {
    "SIEM": {
        "src_ip": ["src_ip", "source_ip", "sourceAddress", "src_addr", "attacker_ip"],
        "dst_ip": ["dst_ip", "dest_ip", "destination_ip", "target_ip", "victim_ip"],
        "src_port": ["src_port", "source_port", "sourcePort"],
        "dst_port": ["dst_port", "dest_port", "destination_port", "target_port"],
        "event_type": ["event_type", "event", "log_type", "alert_type", "signature"],
        "severity": ["severity", "priority", "risk_level", "threat_level"],
        "user": ["user", "username", "account", "user_name"],
        "process": ["process", "process_name", "processPath", "image"],
    },
    "CYBER_SENSOR": {
        "src_ip": ["src_ip", "source_ip", "sourceAddress", "attacker_ip"],
        "dst_ip": ["dst_ip", "dest_ip", "target_ip"],
        "event_type": ["event_type", "event", "detection", "alert_type"],
        "severity": ["severity", "risk_level", "confidence"],
        "payload_size": ["payload_size", "bytes", "data_length"],
    },
    "SATELLITE": {
        "geo_lat": ["lat", "latitude", "geo_lat"],
        "geo_lon": ["lon", "longitude", "geo_lon"],
        "frequency": ["frequency", "freq", "signal_freq"],
        "signal_type": ["signal_type", "type", "modulation"],
        "event_type": ["event_type", "event", "anomaly"],
    },
    "INTELLIGENCE": {
        "threat_actor": ["threat_actor", "actor", "attribution", "group"],
        "campaign": ["campaign", "operation", "campaign_id"],
        "event_type": ["event_type", "event", "indicator_type"],
        "confidence": ["confidence", "reliability", "可信度"],
        "severity": ["severity", "priority", "risk_level"],
    },
    "ENDPOINT": {
        "hostname": ["hostname", "host", "computer_name", "device"],
        "process": ["process", "process_name", "image", "processPath"],
        "file_path": ["file_path", "path", "target", "file"],
        "event_type": ["event_type", "event", "detection_type"],
        "user": ["user", "username", "account"],
    },
    "NETWORK_SENSOR": {
        "src_ip": ["src_ip", "source_ip", "sourceAddress"],
        "dst_ip": ["dst_ip", "dest_ip", "target_ip"],
        "src_port": ["src_port", "source_port"],
        "dst_port": ["dst_port", "dest_port", "target_port"],
        "protocol": ["protocol", "proto"],
        "event_type": ["event_type", "event", "alert"],
    },
    "HONEYPOT": {
        "src_ip": ["src_ip", "source_ip", "attacker_ip", "sourceAddress"],
        "event_type": ["event_type", "event", "interaction_type"],
        "user_agent": ["user_agent", "http_user_agent"],
        "payload": ["payload", "data", "captured_data"],
    },
    "OSINT": {
        "event_type": ["event_type", "event", "indicator_type"],
        "indicator": ["indicator", "value", "ioc"],
        "source_ref": ["source_ref", "reference", "url"],
        "confidence": ["confidence", "reliability"],
    },
}

EVENT_TYPE_NORMALIZATION = {
    "port scan": "Network Discovery (Port Scan)",
    "portscan": "Network Discovery (Port Scan)",
    "port_scan": "Network Discovery (Port Scan)",
    "syn flood": "Network DoS (SYN Flood)",
    "synflood": "Network DoS (SYN Flood)",
    "brute force": "Credential Attack (Brute Force)",
    "bruteforce": "Credential Attack (Brute Force)",
    "brute_force": "Credential Attack (Brute Force)",
    "c2 beacon": "Command and Control (Beacon)",
    "c2_communication": "Command and Control (Beacon)",
    "c2 beaconing": "Command and Control (Beacon)",
    "lateral movement": "Lateral Movement Detected",
    "lateral_movement": "Lateral Movement Detected",
    "data exfiltration": "Data Exfiltration",
    "data_exfiltration": "Data Exfiltration",
    "privilege escalation": "Privilege Escalation",
    "privilege_escalation": "Privilege Escalation",
    "malware": "Malware Detected",
    "ansomware": "Ransomware Activity",
    "phishing": "Phishing Attempt",
    "dns tunnel": "DNS Tunneling",
    "dns_tunnel": "DNS Tunneling",
    "credential dump": "Credential Dump (Mimikatz-like)",
    "credential_dump": "Credential Dump (Mimikatz-like)",
    "mimikatz": "Credential Dump (Mimikatz-like)",
    "ps execution": "Suspicious PowerShell Execution",
    "powershell": "Suspicious PowerShell Execution",
    "suspicious connection": "Suspicious Outbound Connection",
    "suspicious_connection": "Suspicious Outbound Connection",
    "ddos": "Distributed Denial of Service",
    "sqli": "SQL Injection Attempt",
    "sql_injection": "SQL Injection Attempt",
    "xss": "Cross-Site Scripting",
}

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Low",
    "info": "Low",
    "none": "Low",
    "emergency": "Critical",
    "alert": "High",
    "warning": "Medium",
    "error": "High",
}


def _resolve_field(raw_event: dict, aliases: dict) -> Optional[str]:
    for key, alias_list in aliases.items():
        for alias in alias_list:
            val = raw_event.get(alias)
            if val is not None and str(val).strip():
                return str(val).strip()
    return None


def parse_raw_payload(raw_payload: str) -> dict:
    if not raw_payload:
        return {}
    try:
        return json.loads(raw_payload)
    except (json.JSONDecodeError, TypeError):
        pass
    result = {}
    for pair in raw_payload.split(","):
        if ":" in pair:
            k, v = pair.split(":", 1)
            result[k.strip()] = v.strip().strip('"')
    return result


def normalize_event(raw_event: dict, source_type: str) -> dict:
    aliases = FIELD_ALIASES.get(source_type, FIELD_ALIASES["SIEM"])

    raw_payload = raw_event.get("raw_payload", "")
    if raw_payload and isinstance(raw_payload, str):
        parsed = parse_raw_payload(raw_payload)
        merged = {**parsed, **{k: v for k, v in raw_event.items() if v is not None and k != "raw_payload"}}
    else:
        merged = {**raw_event}

    src_ip = _resolve_field(merged, aliases.get("src_ip", []))
    dst_ip = _resolve_field(merged, aliases.get("dst_ip", []))
    event_type = _resolve_field(merged, aliases.get("event_type", []))
    severity = _resolve_field(merged, aliases.get("severity", []))
    user = _resolve_field(merged, aliases.get("user", []))
    process = _resolve_field(merged, aliases.get("process", []))

    normalized_type = EVENT_TYPE_NORMALIZATION.get(event_type.lower().strip(), event_type) if event_type else "Unknown Event"
    normalized_severity = SEVERITY_MAP.get(severity.lower().strip(), severity) if severity else "Medium"

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "event_type": normalized_type,
        "severity": normalized_severity,
        "user": user,
        "process": process,
        "raw_event": merged,
    }


def normalize_alert(raw_event: dict, source_type: str) -> dict:
    normalized = normalize_event(raw_event, source_type)

    alert_id = raw_event.get("id") or raw_event.get("alert_id") or f"AL-{abs(hash(str(raw_event))) % 100000:05d}"

    return {
        "id": alert_id,
        "source": source_type,
        "source_ip": normalized["src_ip"],
        "asset": raw_event.get("asset") or raw_event.get("host") or normalized.get("dst_ip") or "Unknown",
        "asset_ip": raw_event.get("asset_ip") or raw_event.get("host_ip") or normalized.get("dst_ip"),
        "event": raw_event.get("event") or normalized["event_type"],
        "normalized_event": normalized["event_type"],
        "raw_payload": raw_event.get("raw_payload", ""),
        "severity": normalized["severity"],
        "confidence": float(raw_event.get("confidence", 0.0)),
    }
