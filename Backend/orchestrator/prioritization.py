"""
Deterministic incident priority scoring (0–100) for commander triage.
"""

from __future__ import annotations

from typing import Any, Dict, List

from common.schemas import NormalizedThreatEvent, TriageClassification

# Documented weight budget (must sum to 100).
PRIORITY_WEIGHTS: Dict[str, float] = {
    "severity": 25.0,
    "correlation": 20.0,
    "confidence": 20.0,
    "source_agreement": 15.0,
    "blast_radius": 10.0,
    "mitre_impact": 10.0,
}

SEVERITY_SCORE: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.82,
    "medium": 0.55,
    "low": 0.25,
    "info": 0.1,
}

MITRE_IMPACT: Dict[str, float] = {
    "Impact": 1.0,
    "Lateral Movement": 0.95,
    "Command and Control": 0.88,
    "Discovery": 0.72,
    "Unknown": 0.4,
}


def _severity_factor(events: List[NormalizedThreatEvent]) -> float:
    if not events:
        return 0.3
    scores = [SEVERITY_SCORE.get(ev.severity.lower(), 0.5) for ev in events]
    return max(scores)


def compute_priority(
    *,
    events: List[NormalizedThreatEvent],
    correlation_score: float,
    confidence_score: float,
    source_count: int,
    blast_radius_risk: float,
    mitre_tactic: str,
    classification: str,
) -> Dict[str, Any]:
    """
    Compute normalized priority_score 0–100 and priority_level band.
    """
    sev = _severity_factor(events)
    corr = min(1.0, max(0.0, correlation_score))
    conf = min(1.0, max(0.0, confidence_score))
    source_agreement = min(1.0, source_count / 4.0)
    blast = min(1.0, max(0.0, blast_radius_risk))
    mitre = MITRE_IMPACT.get(mitre_tactic, MITRE_IMPACT["Unknown"])

    components = {
        "severity": sev * PRIORITY_WEIGHTS["severity"],
        "correlation": corr * PRIORITY_WEIGHTS["correlation"],
        "confidence": conf * PRIORITY_WEIGHTS["confidence"],
        "source_agreement": source_agreement * PRIORITY_WEIGHTS["source_agreement"],
        "blast_radius": blast * PRIORITY_WEIGHTS["blast_radius"],
        "mitre_impact": mitre * PRIORITY_WEIGHTS["mitre_impact"],
    }

    raw_score = sum(components.values())
    if classification == TriageClassification.FALSE_POSITIVE.value:
        raw_score = min(raw_score, 25.0)
    elif classification == TriageClassification.NEEDS_REVIEW.value:
        raw_score = min(raw_score, 65.0)

    priority_score = int(round(min(100.0, max(0.0, raw_score))))

    if priority_score >= 90:
        level = "CRITICAL"
    elif priority_score >= 75:
        level = "HIGH"
    elif priority_score >= 50:
        level = "MEDIUM"
    else:
        level = "LOW"

    reason_parts = [
        f"severity={sev:.2f}",
        f"correlation={corr:.2f}",
        f"confidence={conf:.2f}",
        f"sources={source_count}",
        f"blast_risk={blast:.2f}",
        f"mitre_tactic={mitre_tactic}",
    ]

    return {
        "priority_score": priority_score,
        "priority_level": level,
        "priority_reason": "; ".join(reason_parts),
        "priority_components": {k: round(v, 2) for k, v in components.items()},
        "weight_documentation": dict(PRIORITY_WEIGHTS),
    }
