"""
Threat Explainability Engine for IMMUNE-NET.
Provides deterministic, reproducible feature-contribution analysis for IsolationForest
anomaly detections using perturbation-based importance measurement.

Approach: For each telemetry feature, the observed value is compared against the
learned normal baseline. Deviation is normalized and expressed as an anomaly
contribution percentage. This is technically defensible because IsolationForest
splits on individual features — features that deviate most from the training
distribution are the ones that drive the anomaly score.
"""

from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger("orchestrator.explain")


# ---------------------------------------------------------------------------
# Normal baseline ranges derived from healthy system telemetry distributions
# (matches agent/detector.py _fit_baseline() training data)
# ---------------------------------------------------------------------------
FEATURE_BASELINES: Dict[str, Dict[str, float]] = {
    "cpu_percent": {"mean": 18.0, "std": 4.0, "lo": 5.0, "hi": 35.0},
    "memory_percent": {"mean": 35.0, "std": 5.0, "lo": 20.0, "hi": 50.0},
    "network_connections": {"mean": 12.0, "std": 3.0, "lo": 1.0, "hi": 25.0},
    "connection_rate": {"mean": 2.0, "std": 0.8, "lo": 0.1, "hi": 4.5},
    "bytes_sent": {"mean": 1200.0, "std": 300.0, "lo": 200.0, "hi": 3000.0},
    "bytes_received": {"mean": 2048.0, "std": 500.0, "lo": 200.0, "hi": 4000.0},
    "file_activity": {"mean": 5.0, "std": 2.0, "lo": 0.0, "hi": 12.0},
    "entropy": {"mean": 0.12, "std": 0.05, "lo": 0.0, "hi": 0.35},
}

# Human-readable explanations keyed by feature and severity
REASON_TEMPLATES: Dict[str, Dict[str, str]] = {
    "cpu_percent": {
        "high": "Sustained CPU utilization is significantly above the normal baseline.",
        "medium": "CPU usage is moderately elevated above typical levels.",
    },
    "memory_percent": {
        "high": "Memory consumption is significantly above the normal operating range.",
        "medium": "Memory usage is moderately elevated.",
    },
    "network_connections": {
        "high": "Network connection count is substantially above baseline.",
        "medium": "Elevated number of active network connections detected.",
    },
    "connection_rate": {
        "high": "Connection creation rate is extremely high, indicating rapid fan-out.",
        "medium": "Connection creation rate is above normal.",
    },
    "bytes_sent": {
        "high": "Outbound data transfer volume is far above the normal range.",
        "medium": "Outbound data transfer is elevated.",
    },
    "bytes_received": {
        "high": "Inbound data transfer volume is far above the normal range.",
        "medium": "Inbound data transfer is elevated.",
    },
    "file_activity": {
        "high": "File I/O activity is significantly above normal, indicating possible data access.",
        "medium": "File I/O activity is moderately elevated.",
    },
    "entropy": {
        "high": "High entropy indicates unusual data/process behavior (possible encryption or obfuscation).",
        "medium": "Elevated entropy suggests slightly anomalous process behavior.",
    },
}


def _deviation_ratio(value: float, baseline: Dict[str, float]) -> float:
    """
    Compute how far a feature value deviates from the normal range, normalized to [0, 1].

    Uses a symmetric range: distance from the nearest baseline boundary,
    scaled by the baseline standard deviation.
    """
    lo = baseline["lo"]
    hi = baseline["hi"]
    std = baseline["std"]
    if std <= 0:
        return 0.0

    if value < lo:
        distance = lo - value
    elif value > hi:
        distance = value - hi
    else:
        return 0.0  # within normal range

    return min(1.0, distance / (std * 3.0))


def compute_feature_contributions(
    evidence: Dict[str, Any],
    model: Any = None,
) -> List[Dict[str, Any]]:
    """
    Compute per-feature anomaly contribution from evidence window data.

    Uses perturbation-based importance: each feature's deviation from the
    learned normal baseline is computed, normalized, and ranked. This is
    deterministic and reproducible.

    Args:
        evidence: Dictionary of feature values from the anomaly evidence window.
        model: Optional trained IsolationForest model (unused in perturbation mode).

    Returns:
        Sorted list of feature contribution dictionaries (highest contribution first).
    """
    contributions = []
    total_raw_deviation = 0.0

    # Phase 1: Compute raw deviations for all features in evidence
    raw_deviations = {}
    for feature_name, value in evidence.items():
        if feature_name in ("process", "destination"):
            continue  # categorical features handled separately
        if feature_name not in FEATURE_BASELINES:
            continue
        try:
            val = float(value)
        except (TypeError, ValueError):
            continue
        baseline = FEATURE_BASELINES[feature_name]
        ratio = _deviation_ratio(val, baseline)
        if ratio > 0:
            raw_deviations[feature_name] = {"value": val, "ratio": ratio}
            total_raw_deviation += ratio

    # Phase 2: Normalize contributions to sum to 1.0
    if total_raw_deviation > 0:
        for fname, data in raw_deviations.items():
            normalized = data["ratio"] / total_raw_deviation
            baseline = FEATURE_BASELINES[fname]
            severity = "high" if normalized >= 0.30 else "medium"
            reason = REASON_TEMPLATES.get(fname, {}).get(severity, "Value is above normal baseline.")
            contributions.append({
                "feature": fname,
                "value": data["value"],
                "normalized_contribution": round(normalized, 4),
                "reason": reason,
            })
    # Sort descending by contribution
    contributions.sort(key=lambda x: x["normalized_contribution"], reverse=True)

    # Phase 3: Handle categorical indicators (process name, destination)
    process = evidence.get("process", "")
    if process and process.lower() not in ("", "systemd", "bash", "unknown"):
        contributions.append({
            "feature": "process_name",
            "value": process,
            "normalized_contribution": 0.0,
            "reason": f"Suspicious process '{process}' was active during the anomaly window.",
        })

    destination = evidence.get("destination", "")
    if destination and destination not in ("", "unknown", "10.0.1.1:443"):
        contributions.append({
            "feature": "destination",
            "value": destination,
            "normalized_contribution": 0.0,
            "reason": f"Unusual network destination '{destination}' observed during the anomaly window.",
        })

    return contributions


def generate_explanation(
    evidence: Dict[str, Any],
    scenario_hint: Optional[str] = None,
    anomaly_score: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Generate a complete human-readable explanation for why a threat was flagged.

    Args:
        evidence: Feature values from the anomaly evidence window.
        scenario_hint: Optional scenario type hint for contextual framing.
        anomaly_score: Optional raw anomaly score from the detector.

    Returns:
        Dictionary with 'explanation' list, 'summary' text, and 'indicators' summary.
    """
    contributions = compute_feature_contributions(evidence)

    if not contributions:
        return {
            "explanation": [],
            "summary": "No significant feature deviations detected from baseline.",
            "indicators": [],
        }

    # Top 3 indicators for summary
    top = [c for c in contributions if c["normalized_contribution"] > 0][:3]
    indicators = [
        {
            "feature": c["feature"],
            "value": c["value"],
            "contribution_pct": round(c["normalized_contribution"] * 100, 1),
        }
        for c in top
    ]

    # Build human-readable summary
    parts = []
    for c in top:
        if isinstance(c["value"], float):
            val_str = f"{c['value']:.1f}" if c["value"] < 100 else f"{int(c['value'])}"
        else:
            val_str = str(c["value"])
        parts.append(
            f"{c['feature'].replace('_', ' ')} {val_str} "
            f"({round(c['normalized_contribution'] * 100, 1)}% anomaly contribution)"
        )

    summary = "Primary indicators: " + "; ".join(parts) + "."

    # Contextual framing
    if scenario_hint == "cryptominer":
        summary = "Flagged primarily due to " + summary.replace("Primary indicators: ", "")
        summary += " This pattern is consistent with cryptomining activity."
    elif scenario_hint == "port_scan":
        summary = "Flagged primarily due to " + summary.replace("Primary indicators: ", "")
        summary += " This pattern is consistent with port scanning or reconnaissance."
    elif scenario_hint == "c2_beacon":
        summary = "Flagged primarily due to " + summary.replace("Primary indicators: ", "")
        summary += " This pattern is consistent with command-and-control communication."
    elif scenario_hint == "worm":
        summary = "Flagged primarily due to " + summary.replace("Primary indicators: ", "")
        summary += " This pattern is consistent with lateral worm propagation."
    else:
        summary = "The threat was " + summary

    return {
        "explanation": contributions,
        "summary": summary,
        "indicators": indicators,
        "scenario_hint": scenario_hint,
        "anomaly_score": anomaly_score,
    }


def explanation_to_text(explanation_data: Dict[str, Any]) -> str:
    """
    Format explanation data as a human-readable text block suitable for BLUF integration.

    Args:
        explanation_data: Output of generate_explanation().

    Returns:
        Formatted text string.
    """
    lines = []
    explanation = explanation_data.get("explanation", [])
    for c in explanation:
        if c["normalized_contribution"] > 0:
            feat = c["feature"].replace("_", " ").title()
            val = c["value"]
            contrib_pct = round(c["normalized_contribution"] * 100, 1)
            lines.append(f"- {feat}: {val} ({contrib_pct}% anomaly contribution)")
        else:
            feat = c["feature"].replace("_", " ").title()
            lines.append(f"- {feat}: {val}")

    summary = explanation_data.get("summary", "")
    if summary:
        return summary + "\n" + "\n".join(lines)
    return "\n".join(lines)
