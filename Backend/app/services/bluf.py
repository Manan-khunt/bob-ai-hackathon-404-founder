from typing import Optional, List
import os


def generate_bluf(
    incident: dict,
    alerts: List[dict],
    mitre_techniques: List[dict],
    watsonx_enabled: bool = False,
) -> dict:
    if watsonx_enabled and os.getenv("WATSONX_API_KEY"):
        try:
            return _generate_bluf_watsonx(incident, alerts, mitre_techniques)
        except Exception:
            pass

    return _generate_bluf_deterministic(incident, alerts, mitre_techniques)


def _generate_bluf_deterministic(
    incident: dict,
    alerts: List[dict],
    mitre_techniques: List[dict],
) -> dict:
    severity = incident.get("severity", "Medium").upper()
    source_count = len(incident.get("sources", []))
    alert_count = len(alerts)
    confidence = incident.get("confidence", 0.5)
    affected_assets = incident.get("affected_assets", [])
    asset_names = [a.get("asset", "Unknown") for a in affected_assets]
    threat_type = incident.get("threat_type", "Unknown")
    title = incident.get("title", "Security Incident")

    tactic_names = list(set(t.get("tactic", "Unknown") for t in mitre_techniques))
    technique_names = [t.get("name", "Unknown") for t in mitre_techniques]

    if severity == "CRITICAL":
        impact = (
            f"Critical severity incident involving {len(affected_assets)} asset(s) ({', '.join(asset_names[:3])}). "
            f"Multiple attack vectors detected across {source_count} source(s). "
            f"Immediate containment required to prevent further lateral movement."
        )
        recommended_action = (
            "Isolate affected assets immediately. Initiate incident response procedure. "
            "Engage threat hunting team. Consider network segmentation."
        )
    elif severity == "HIGH":
        impact = (
            f"High severity incident affecting {len(affected_assets)} asset(s) ({', '.join(asset_names[:3])}). "
            f"Evidence of malicious activity from {alert_count} alert(s) across {source_count} source(s)."
        )
        recommended_action = (
            "Monitor closely. Prepare for containment if escalation occurs. "
            "Review related indicators and update detection rules."
        )
    elif severity == "MEDIUM":
        impact = (
            f"Medium severity activity detected on {len(affected_assets)} asset(s) ({', '.join(asset_names[:3])}). "
            f"Correlation from {source_count} source(s) with {alert_count} alert(s)."
        )
        recommended_action = (
            "Continue monitoring. Validate indicators. "
            "Consider additional logging for affected assets."
        )
    else:
        impact = (
            f"Low severity activity on {len(affected_assets)} asset(s) ({', '.join(asset_names[:3])}). "
            f"Likely benign but requires review."
        )
        recommended_action = "Review alert details. No immediate action required."

    evidence_items = []
    for alert in alerts[:5]:
        evidence_items.append(
            f"[{alert.get('source', 'Unknown')}] {alert.get('event', 'Unknown event')} "
            f"on {alert.get('asset', 'Unknown')} (confidence: {alert.get('confidence', 0):.0%})"
        )

    if mitre_techniques:
        mitre_str = ", ".join(f"{t['id']} ({t['name']})" for t in mitre_techniques[:4])
        evidence_items.append(f"MITRE techniques mapped: {mitre_str}")

    bottom_line = (
        f"{title} ({threat_type}) — {severity} priority. "
        f"{confidence:.0%} confidence based on {alert_count} correlated alert(s) "
        f"from {source_count} source(s). "
        f"Tactics: {', '.join(tactic_names) if tactic_names else 'Analyzing'}. "
        f"Affected: {', '.join(asset_names[:3])}."
    )

    return {
        "bottomLine": bottom_line,
        "impact": impact,
        "evidence": evidence_items,
        "mitreMapping": [{"id": t["id"], "name": t["name"]} for t in mitre_techniques[:6]],
        "priorityScore": incident.get("priority_score", 0),
        "priorityLevel": incident.get("priority_level", "LOW"),
        "recommendedAction": recommended_action,
        "generatedBy": "deterministic",
    }


def _generate_bluf_watsonx(
    incident: dict,
    alerts: List[dict],
    mitre_techniques: List[dict],
) -> dict:
    from ..integrations.watsonx import watsonx_generate
    result = watsonx_generate(
        prompt=f"Generate BLUF intelligence briefing for: {incident.get('title', 'Unknown')}",
        context={
            "incident": incident,
            "alerts_count": len(alerts),
            "mitre": [t["id"] for t in mitre_techniques],
        },
    )
    if result:
        base = _generate_bluf_deterministic(incident, alerts, mitre_techniques)
        base["bottomLine"] = result.get("text", base["bottomLine"])
        base["generatedBy"] = "watsonx"
        return base
    return _generate_bluf_deterministic(incident, alerts, mitre_techniques)
