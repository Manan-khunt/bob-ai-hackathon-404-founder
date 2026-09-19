"""
Structured BLUF object for commander dashboards and MCP tools.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from orchestrator.bluf import generate_bluf_summary
from orchestrator.mitre_mapping import get_mitre_technique
from orchestrator.recommend import get_recommendation


def build_mitre_enriched(scenario_type: str, confidence: float, evidence_ids: list) -> Dict[str, Any]:
    base = get_mitre_technique(scenario_type)
    return {
        "technique_id": base.get("technique_id"),
        "technique_name": base.get("technique_name"),
        "tactic": base.get("tactic"),
        "confidence": round(confidence, 4),
        "evidence": list(evidence_ids),
    }


def generate_bluf_object(
    *,
    incident: Dict[str, Any],
    mitre: Dict[str, Any],
    priority_score: int,
    priority_level: str,
    classification: str,
    antibody: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    attack_type = incident.get("attack_type") or incident.get("scenario_type") or "unknown"
    node_id = incident.get("node_id") or incident.get("asset_id") or "unknown"
    conf = incident.get("confidence") or incident.get("confidence_score") or 0.0
    summary = generate_bluf_summary(incident, antibody=antibody)

    recommended = (
        incident.get("recommended_neutralization_action")
        or (antibody or {}).get("neutralization_action")
        or get_recommendation(attack_type)
    )

    return {
        "bottom_line": f"{classification}: {attack_type} activity on {node_id} requires commander attention.",
        "impact": f"Priority {priority_level} ({priority_score}/100) — MITRE {mitre.get('technique_id')} ({mitre.get('tactic')}).",
        "evidence": incident.get("evidence_event_ids") or mitre.get("evidence") or [],
        "mitre": mitre,
        "priority": {"score": priority_score, "level": priority_level},
        "recommended_action": recommended,
        "full_summary": summary,
    }
