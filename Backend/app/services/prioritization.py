from ..config import PRIORITY_WEIGHTS


def compute_priority_score(
    correlation_score: float,
    severity: str,
    confidence: float,
    source_count: int,
    asset_criticality: float = 0.5,
) -> int:
    sev_value = {
        "critical": 1.0,
        "high": 0.8,
        "medium": 0.5,
        "low": 0.2,
    }.get(severity.lower() if severity else "medium", 0.5)

    diversity_score = min(source_count / 4.0, 1.0)

    w = PRIORITY_WEIGHTS
    raw_score = (
        correlation_score * w["correlation_score"]
        + sev_value * w["severity_value"]
        + confidence * w["confidence"]
        + diversity_score * w["multi_source_diversity"]
        + asset_criticality * w["asset_criticality"]
    )

    total_weight = sum(w.values())
    normalized = (raw_score / total_weight) * 100.0
    return max(0, min(100, round(normalized)))


def priority_level(score: int) -> str:
    if score >= 90:
        return "CRITICAL"
    elif score >= 75:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    elif score >= 25:
        return "LOW"
    else:
        return "INFO"


def priority_rank(score: int) -> str:
    level = priority_level(score)
    rank_map = {
        "CRITICAL": "01",
        "HIGH": "02",
        "MEDIUM": "03",
        "LOW": "04",
        "INFO": "05",
    }
    return rank_map.get(level, "05")
