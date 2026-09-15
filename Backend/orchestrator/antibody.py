"""
Deterministic Normalized Antibody Generator for IMMUNE-NET.
Calculates canonical cryptographic signatures and constructs standardized Digital Antibody payloads
containing detection rules, neutralization commands, MITRE ATT&CK mappings, and remediation recommendations.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from orchestrator.recommend import get_recommendation
from orchestrator.mitre_mapping import get_mitre_technique


def signature_for(feature_vector: Dict[str, Any], detection_rule: Dict[str, Any], action: Dict[str, Any]) -> str:
    """
    Compute deterministic SHA-256 hash over canonical representation of antibody definition.

    Args:
        feature_vector: Extracted biomarker features and thresholds.
        detection_rule: Rule specification evaluated by endpoint agents.
        action: Containment or neutralization action specification.

    Returns:
        Hexadecimal SHA-256 signature string.
    """
    payload = json.dumps(
        {"feature_vector": feature_vector, "detection_rule": detection_rule, "action": action},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def generate_antibody(
    feature_vector: Dict[str, Any],
    threat_class: str,
    confidence: float,
    detection_rule: Dict[str, Any],
    action: Dict[str, Any],
    issued_by: str = "immune-net-orchestrator",
    version: int = 1,
    ttl_days: int = 30,
) -> Dict[str, Any]:
    """
    Generate normalized antibody payload enriched with MITRE ATT&CK mapping and hardening recommendation.

    Args:
        feature_vector: Biomarker feature vector of the confirmed threat.
        threat_class: Classification name (e.g. 'cryptominer', 'port_scan').
        confidence: Confidence score of detection (0.0 - 1.0).
        detection_rule: Structured rule dictionary.
        action: Structured neutralization action dictionary.
        issued_by: Issuer identifier.
        version: Schema/rule version integer.
        ttl_days: Validity time-to-live in days.

    Returns:
        Dict representing the complete Digital Antibody.
    """
    signature = signature_for(feature_vector, detection_rule, action)
    mitre = get_mitre_technique(threat_class)
    return {
        "antibody_id": f"ab-{signature[:16]}",
        "signature": signature,
        "threat": {"class": threat_class, "confidence": confidence},
        "detection_rule": detection_rule,
        "neutral_action": action,
        "issued_by": issued_by,
        "version": version,
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=ttl_days)).isoformat(),
        "recommendation": get_recommendation(threat_class),
        "mitre": mitre,
    }
