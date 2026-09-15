"""
MITRE ATT&CK Framework Mapping Engine for IMMUNE-NET.
Maps detected attack patterns and anomalies to standardized MITRE ATT&CK Enterprise Matrix
tactics and techniques for threat intelligence correlation.
"""

from typing import Dict, Any

# Standardized MITRE ATT&CK Technique Lookup Table
MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "cryptominer": {
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
        "tactic": "Impact",
    },
    "crypto_ransomware": {
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
        "tactic": "Impact",
    },
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "syn_cytokine_flood": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    "c2_beacon": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
    "exfil_parasite": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
    },
    "worm": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
    },
    "worm_ravage": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
    },
    "kernel_blight": {
        "technique_id": "T1210",
        "technique_name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement",
    },
}

UNKNOWN_TECHNIQUE: Dict[str, str] = {
    "technique_id": "UNKNOWN",
    "technique_name": "Unclassified",
    "tactic": "Unknown",
}


def get_mitre_technique(attack_type: str) -> Dict[str, str]:
    """
    Retrieve standardized MITRE ATT&CK technique and tactic mapping for an attack type.

    Args:
        attack_type: Attack or threat scenario name (e.g., 'cryptominer', 'port_scan', 'c2_beacon', 'worm').

    Returns:
        Dict with keys 'technique_id', 'technique_name', and 'tactic'.
    """
    if not attack_type:
        return UNKNOWN_TECHNIQUE.copy()
    key = str(attack_type).strip().lower()
    return MITRE_TECHNIQUES.get(key, UNKNOWN_TECHNIQUE).copy()
