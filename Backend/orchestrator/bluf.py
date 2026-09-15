"""
Bottom Line Up Front (BLUF) Incident Summary Generator.
Provides concise executive-level operational and threat intelligence summaries
formatted for immediate triage by commanders, SOC analysts, and security engineers.

Integrates Watsonx.ai Granite for AI-enriched BLUF generation with deterministic
rule-based fallback. Includes explainability data from feature contribution analysis.
"""

from typing import Dict, Any, Optional
from orchestrator.mitre_mapping import get_mitre_technique
from orchestrator.recommend import get_recommendation
from orchestrator.watsonx import generate_watsonx_bluf, generate_watsonx_narrative
from orchestrator.apt_fingerprint import fingerprint_threat_actor, detected_techniques_for
from orchestrator.explain import generate_explanation, explanation_to_text


def generate_bluf_summary(
    incident: Dict[str, Any],
    antibody: Optional[Dict[str, Any]] = None,
    total_nodes: int = 8,
    immunized_count: int = 8,
    explanation: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Generate a standardized BLUF incident summary string for commander/analyst rapid triage.

    First attempts Watsonx Granite for a 3-sentence AI-enriched BLUF.
    Falls back to the detailed rule-based BLUF on any failure.

    Args:
        incident: Incident or confirmed threat dictionary.
        antibody: Optional associated antibody dictionary.
        total_nodes: Total number of active swarm nodes in fleet.
        immunized_count: Number of nodes protected/fortified.
        explanation: Optional explanation data from explain.generate_explanation().

    Returns:
        Structured multi-line BLUF text string.
    """
    node_id = incident.get("node_id") or incident.get("affected_agent", "unknown-node")
    attack_type = incident.get("attack_type") or incident.get("scenario") or incident.get("scenario_type", "unknown")
    status = incident.get("status", "confirmed")

    # Format confidence percentage
    raw_conf = incident.get("confidence")
    if raw_conf is None:
        raw_conf = incident.get("confidence_score", 1.0)
    try:
        conf_val = float(raw_conf)
        if conf_val <= 1.0:
            confidence_pct = int(round(conf_val * 100))
        else:
            confidence_pct = int(round(conf_val))
    except (ValueError, TypeError):
        confidence_pct = 99

    # Determine neutralization action
    neutral_action = None
    if antibody:
        action_obj = antibody.get("neutral_action") or antibody.get("neutralization_action")
        if isinstance(action_obj, dict):
            neutral_action = action_obj.get("type")
        elif isinstance(action_obj, str):
            neutral_action = action_obj

    if not neutral_action:
        neutral_action = incident.get("recommended_neutralization_action") or "quarantine_source"

    detected_at = (
        incident.get("detected_at")
        or incident.get("timestamp")
        or incident.get("confirmed_at")
        or incident.get("sent_at", "N/A")
    )

    mitre = incident.get("mitre") or (antibody.get("mitre") if antibody else None) or get_mitre_technique(attack_type)
    technique_id = mitre.get("technique_id", "UNKNOWN")
    technique_name = mitre.get("technique_name", "Unclassified")
    tactic = mitre.get("tactic", "Unknown")

    owner_id = incident.get("owner_id", "admin_1")
    recommendation = (
        incident.get("recommendation")
        or (antibody.get("recommendation") if antibody else None)
        or get_recommendation(attack_type)
    )

    # Threat-actor attribution via MITRE technique fingerprinting.
    technique_ids = detected_techniques_for(attack_type, mitre)
    attributions = incident.get("threat_actor_attributions") or fingerprint_threat_actor(technique_ids)
    top_actor = attributions[0] if attributions else None

    # --- Attempt Watsonx Granite BLUF ---
    threat_context = {
        "threat_type": attack_type,
        "severity": "critical" if confidence_pct >= 95 else "high" if confidence_pct >= 85 else "medium",
        "confidence": f"{confidence_pct}%",
        "node_id": node_id,
        "process": (antibody or {}).get("process") or incident.get("process"),
        "entropy": incident.get("entropy") or (antibody or {}).get("entropy"),
        "cpu_usage": incident.get("cpu_usage") or (antibody or {}).get("cpu"),
        "memory_usage": incident.get("memory_usage"),
        "connections": incident.get("connections"),
        "connection_rate": incident.get("connection_rate"),
    }

    blast_radius_data = incident.get("blast_radius")
    apt_data = {"top_match": top_actor} if top_actor and top_actor.get("confidence_pct", 0) > 0 else None

    watsonx_bluf = generate_watsonx_bluf(
        threat_context=threat_context,
        explanation_data=explanation,
        mitre_data=mitre,
        apt_data=apt_data,
        blast_radius_data=blast_radius_data,
        containment_status="active (node quarantined)",
        immune_memory_status=f"digital antibody synthesized ({antibody.get('antibody_id', 'pending')})" if antibody else "pending synthesis",
    )

    if watsonx_bluf:
        return watsonx_bluf

    # --- Fallback: Detailed rule-based BLUF ---
    if attribution_line := _format_attribution(attributions):
        pass
    else:
        attribution_line = "- Threat actor attribution: unclassified"

    # Optional Watsonx.ai natural-language details enrichment (non-BLUF narrative)
    watsonx_narrative = generate_watsonx_narrative(
        attack_type=attack_type,
        node_id=node_id,
        technique_id=technique_id,
        technique_name=technique_name,
        tactic=tactic,
        recommendation=recommendation,
    )

    # --- Build the BLUF summary ---
    bottom_line = f"BOTTOM LINE: Node {node_id} compromised by {attack_type} — {status}."
    confidence_line = f"Confidence: {confidence_pct}%. Action taken: {neutral_action}."

    # Evidence block
    evidence_lines = [
        f"DETAILS:",
        f"- Detection time: {detected_at}",
        f"- MITRE ATT&CK: {technique_id} — {technique_name} ({tactic})",
        attribution_line,
        f"- Affected node owner: {owner_id}",
        f"- Recommended hardening: {recommendation}",
        f"- Network-wide immunity status: {immunized_count}/{total_nodes} nodes protected",
    ]

    # Include explanation data if available
    if explanation and explanation.get("explanation"):
        evidence_lines.append("- ANOMALY EXPLANATION:")
        for c in explanation["explanation"]:
            if c.get("normalized_contribution", 0) > 0:
                feat = c["feature"].replace("_", " ").title()
                val = c["value"]
                contrib = round(c["normalized_contribution"] * 100, 1)
                evidence_lines.append(f"  - {feat}: {val} ({contrib}% anomaly contribution)")
                evidence_lines.append(f"    {c.get('reason', '')}")

    if watsonx_narrative:
        evidence_lines.append(f"- AI Narrative: {watsonx_narrative}")

    return f"{bottom_line}\n{confidence_line}\n\n" + "\n".join(evidence_lines)


def _format_attribution(attributions: list) -> str:
    """Format threat actor attribution lines."""
    top_actor = attributions[0] if attributions else None
    if top_actor and top_actor.get("confidence_pct", 0) > 0:
        return (
            f"- Threat actor attribution: {top_actor['name']} ({top_actor['confidence_pct']}% confidence, "
            f"{len(top_actor.get('matched_techniques', []))} matched techniques)\n"
            f"- Top actor candidates: {', '.join(a['name'] for a in attributions[:3])}"
        )
    return ""
