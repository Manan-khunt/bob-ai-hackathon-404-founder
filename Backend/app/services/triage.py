from typing import Optional
from ..config import TRIAGE_THRESHOLDS


def triage_event(
    correlation_score: float,
    is_honeypot: bool = False,
    source_count: int = 1,
    severity: str = "Medium",
) -> str:
    score = correlation_score

    if is_honeypot:
        score += TRIAGE_THRESHOLDS["honeypot_bonus"]

    multi_source_bonus = min(
        (source_count - 1) * TRIAGE_THRESHOLDS["multi_source_bonus_per_source"],
        TRIAGE_THRESHOLDS["multi_source_cap"],
    )
    score += multi_source_bonus

    if score >= TRIAGE_THRESHOLDS["min_correlation_score_for_threat"]:
        return "TRUE_THREAT"
    elif score <= 0.25:
        return "FALSE_POSITIVE"
    else:
        return "NEEDS_REVIEW"


def triage_alert(alert: dict) -> str:
    correlation_score = alert.get("correlation_score", 0.0)
    source_type = alert.get("source_type", "")
    is_honeypot = source_type == "HONEYPOT"
    severity = alert.get("severity", "Medium")

    result = triage_event(
        correlation_score=correlation_score,
        is_honeypot=is_honeypot,
        severity=severity,
    )
    return result


def classify_confidence(triage_result: str, correlation_score: float) -> float:
    base_confidence = {
        "TRUE_THREAT": 0.80,
        "NEEDS_REVIEW": 0.50,
        "FALSE_POSITIVE": 0.30,
    }.get(triage_result, 0.50)

    adjusted = base_confidence + (correlation_score * 0.20)
    return round(min(adjusted, 1.0), 4)
