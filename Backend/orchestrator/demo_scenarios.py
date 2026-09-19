"""
Deterministic hackathon demo scenarios for the threat pipeline.
All payloads are synthetic demo intelligence — not live production feeds.
"""

from __future__ import annotations

from typing import Any, Dict, List

from common.schemas import utc_iso_now

# Fixed demo anchor time for reproducible correlation windows.
_DEMO_TS = utc_iso_now()


def _ts(offset_seconds: int = 0) -> str:
    return _DEMO_TS


DEMO_SCENARIOS: Dict[str, List[Dict[str, Any]]] = {
    "coordinated_intrusion": [
        {
            "source_type": "SIEM",
            "timestamp": _ts(0),
            "src_ip": "203.0.113.45",
            "host": "node-beta",
            "event": "port_scan",
            "severity": "high",
            "confidence": 0.88,
            "scenario": "port_scan",
            "correlation_key": "demo-coordinated|node-beta|203.0.113.45|intrusion",
            "demo_synthetic": True,
            "message": "SIEM: external host sweeping internal ports on node-beta",
        },
        {
            "source_type": "CYBER_SENSOR",
            "timestamp": _ts(15),
            "sensor_id": "cyber-edge-01",
            "alert_type": "connection_spike",
            "target": "node-beta",
            "source_ip": "203.0.113.45",
            "severity": "high",
            "confidence": 0.90,
            "scenario": "port_scan",
            "correlation_key": "demo-coordinated|node-beta|203.0.113.45|intrusion",
            "demo_synthetic": True,
        },
        {
            "source_type": "HONEYPOT",
            "timestamp": _ts(30),
            "attacker_ip": "203.0.113.45",
            "attack_vector": "honeypot_probe",
            "severity": "critical",
            "confidence": 0.93,
            "scenario": "port_scan",
            "asset_id": "node-beta",
            "correlation_key": "demo-coordinated|node-beta|203.0.113.45|intrusion",
            "demo_synthetic": True,
        },
        {
            "source_type": "ENDPOINT",
            "timestamp": _ts(45),
            "agent_id": "node-beta",
            "anomaly_type": "endpoint_anomaly",
            "anomaly_score": 91,
            "severity": "critical",
            "confidence": 0.92,
            "scenario": "port_scan",
            "source_ip": "203.0.113.45",
            "correlation_key": "demo-coordinated|node-beta|203.0.113.45|intrusion",
            "evidence_window": {"connection_rate": 24.0, "process": "syn_scan", "network_connections": 120},
            "demo_synthetic": True,
        },
    ],
    "benign_noise": [
        {
            "source_type": "ENDPOINT",
            "timestamp": _ts(0),
            "agent_id": "node-alpha",
            "anomaly_type": "process_anomaly",
            "anomaly_score": 22,
            "severity": "low",
            "confidence": 0.28,
            "indicators": {"known_benign_process": True},
            "evidence": {"process": "chrome.exe"},
            "correlation_key": "demo-noise|node-alpha|benign",
            "demo_synthetic": True,
        },
        {
            "source_type": "ENDPOINT",
            "timestamp": _ts(10),
            "agent_id": "node-alpha",
            "anomaly_type": "process_anomaly",
            "anomaly_score": 18,
            "severity": "low",
            "confidence": 0.25,
            "indicators": {"known_benign_process": True},
            "evidence": {"process": "chrome.exe"},
            "correlation_key": "demo-noise|node-alpha|benign",
            "demo_synthetic": True,
        },
        {
            "source_type": "ENDPOINT",
            "timestamp": _ts(20),
            "agent_id": "node-alpha",
            "anomaly_type": "process_anomaly",
            "anomaly_score": 20,
            "severity": "low",
            "confidence": 0.30,
            "indicators": {"known_benign_process": True},
            "evidence": {"process": "chrome.exe"},
            "correlation_key": "demo-noise|node-alpha|benign",
            "demo_synthetic": True,
        },
    ],
    "needs_review": [
        {
            "source_type": "SIEM",
            "timestamp": _ts(0),
            "src_ip": "198.51.100.10",
            "host": "node-gamma",
            "event": "suspicious_login",
            "severity": "medium",
            "confidence": 0.62,
            "correlation_key": "demo-review|node-gamma",
            "demo_synthetic": True,
        },
        {
            "source_type": "NETWORK_SENSOR",
            "timestamp": _ts(120),
            "src": "198.51.100.10",
            "dst": "node-gamma:443",
            "alert": "unusual_volume",
            "severity": "medium",
            "confidence": 0.58,
            "asset_id": "node-gamma",
            "correlation_key": "demo-review|node-gamma",
            "demo_synthetic": True,
        },
    ],
}


def get_demo_scenario(name: str) -> List[Dict[str, Any]]:
    key = (name or "").strip().lower()
    if key not in DEMO_SCENARIOS:
        raise KeyError(f"Unknown demo scenario: {name}")
    return [dict(ev) for ev in DEMO_SCENARIOS[key]]
