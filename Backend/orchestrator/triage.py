"""
Deterministic threat triage: TRUE_THREAT / FALSE_POSITIVE / NEEDS_REVIEW.
"""

from __future__ import annotations

from typing import Any, Dict, List

from common.schemas import NormalizedThreatEvent, TriageClassification

TRIAGE_RULE_VERSION = "triage-deterministic-v1"

# Thresholds (documented for examiner audit).
TRUE_CORRELATION_MIN = 0.72
TRUE_CONFIDENCE_MIN = 0.82
TRUE_SOURCE_MIN = 3
TRUE_EVIDENCE_MIN = 3

FP_CORRELATION_MAX = 0.42
FP_SOURCE_MAX = 1
FP_CONFIDENCE_MAX = 0.55


def classify_triage(
    *,
    correlation_score: float,
    confidence_score: float,
    evidence_count: int,
    source_count: int,
    events: List[NormalizedThreatEvent],
) -> Dict[str, Any]:
    """
    Deterministic triage — no randomness.
    """
    benign_markers = sum(
        1
        for ev in events
        if ev.indicators.get("benign")
        or ev.indicators.get("known_benign_process")
        or (ev.evidence.get("process") or "").lower() in ("chrome.exe", "systemd", "windows_update")
    )
    weak_anomaly = all(ev.confidence < 0.45 for ev in events) if events else True

    reasons: List[str] = []

    if (
        correlation_score >= TRUE_CORRELATION_MIN
        and confidence_score >= TRUE_CONFIDENCE_MIN
        and source_count >= TRUE_SOURCE_MIN
        and evidence_count >= TRUE_EVIDENCE_MIN
        and benign_markers == 0
    ):
        classification = TriageClassification.TRUE_THREAT.value
        reasons.append(
            f"High correlation ({correlation_score:.2f}), confidence ({confidence_score:.2f}), "
            f"{source_count} corroborating sources, {evidence_count} evidence items."
        )
    elif benign_markers >= 2 and source_count <= FP_SOURCE_MAX:
        classification = TriageClassification.FALSE_POSITIVE.value
        reasons.append(
            f"Repeated single-source benign indicators ({benign_markers} events) — classified as noise."
        )
    elif (
        correlation_score <= FP_CORRELATION_MAX
        and source_count <= FP_SOURCE_MAX
        and (confidence_score <= FP_CONFIDENCE_MAX or benign_markers > 0 or weak_anomaly)
    ):
        classification = TriageClassification.FALSE_POSITIVE.value
        if benign_markers:
            reasons.append("Known benign process / indicator flagged as noise.")
        if weak_anomaly:
            reasons.append("Weak anomaly scores with no corroboration.")
        reasons.append(
            f"Single-source/low correlation ({correlation_score:.2f}) below confirmation threshold."
        )
    else:
        classification = TriageClassification.NEEDS_REVIEW.value
        reasons.append(
            f"Ambiguous evidence: correlation={correlation_score:.2f}, confidence={confidence_score:.2f}, "
            f"sources={source_count}."
        )

    return {
        "classification": classification,
        "classification_reason": " ".join(reasons),
        "confidence": round(confidence_score, 4),
        "evidence_count": evidence_count,
        "source_count": source_count,
        "rule_version": TRIAGE_RULE_VERSION,
    }
