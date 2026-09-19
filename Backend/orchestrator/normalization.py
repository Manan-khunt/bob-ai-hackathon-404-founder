"""
Multi-source threat event normalization for IMMUNE-NET.
Transforms heterogeneous source payloads into NormalizedThreatEvent records.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from common.schemas import NormalizedThreatEvent, SourceType, generate_uuid, utc_iso_now

SUPPORTED_SOURCE_TYPES = {s.value for s in SourceType}

# Canonical field aliases per source family (demo + live JSON shapes).
_FIELD_ALIASES: Dict[str, Dict[str, str]] = {
    "SIEM": {"src_ip": "source_ip", "event": "event_type", "host": "asset_id", "severity": "severity"},
    "CYBER_SENSOR": {"sensor_id": "source_name", "alert_type": "event_type", "target": "asset_id"},
    "SATELLITE": {"observation_type": "event_type", "ground_asset": "asset_id"},
    "INTELLIGENCE_REPORT": {"report_type": "event_type", "target_asset": "asset_id"},
    "HONEYPOT": {"attack_vector": "event_type", "attacker_ip": "source_ip"},
    "ENDPOINT": {"agent_id": "asset_id", "anomaly_type": "event_type", "host_id": "asset_id"},
    "NETWORK_SENSOR": {"alert": "event_type", "dst": "destination", "src": "source_ip"},
}


def _parse_timestamp(raw: Any) -> str:
    if not raw:
        return utc_iso_now()
    if isinstance(raw, str):
        return raw
    return utc_iso_now()


def _infer_source_type(payload: Dict[str, Any]) -> str:
    explicit = payload.get("source_type") or payload.get("sourceType")
    if explicit:
        key = str(explicit).upper()
        if key in SUPPORTED_SOURCE_TYPES:
            return key
    if "attack_vector" in payload or payload.get("honeypot"):
        return SourceType.HONEYPOT.value
    if "anomaly_type" in payload or "anomaly_score" in payload:
        return SourceType.ENDPOINT.value
    if "observation_type" in payload:
        return SourceType.SATELLITE.value
    if "report_type" in payload or "intel_id" in payload:
        return SourceType.INTELLIGENCE_REPORT.value
    if "sensor_id" in payload or "cyber_sensor" in payload:
        return SourceType.CYBER_SENSOR.value
    if "src_ip" in payload and "event" in payload:
        return SourceType.SIEM.value
    if "alert" in payload and ("src" in payload or "dst" in payload):
        return SourceType.NETWORK_SENSOR.value
    return SourceType.SIEM.value


def _apply_aliases(source_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(payload)
    for src_key, dst_key in _FIELD_ALIASES.get(source_type, {}).items():
        if src_key in merged and dst_key not in merged:
            merged[dst_key] = merged[src_key]
    return merged


def _build_correlation_key(source_type: str, asset_id: str, source_ip: str, event_type: str) -> str:
    parts = [source_type, asset_id or "unknown", source_ip or "unknown", event_type or "unknown"]
    return "|".join(p.lower().strip() for p in parts)


def normalize_raw_event(
    payload: Dict[str, Any],
    *,
    default_source_type: Optional[str] = None,
) -> NormalizedThreatEvent:
    """
    Normalize a single heterogeneous source record into NormalizedThreatEvent.

    Preserves the original payload in raw_event.
    """
    raw_event = dict(payload)
    source_type = default_source_type or _infer_source_type(payload)
    source_type = str(source_type).upper()
    if source_type not in SUPPORTED_SOURCE_TYPES:
        source_type = SourceType.SIEM.value

    body = _apply_aliases(source_type, payload)

    event_id = body.get("event_id") or generate_uuid("norm-")
    source_name = (
        body.get("source_name")
        or body.get("sensor_id")
        or body.get("siem_name")
        or f"demo-{source_type.lower()}"
    )
    timestamp = _parse_timestamp(body.get("timestamp"))
    asset_id = (
        body.get("asset_id")
        or body.get("agent_id")
        or body.get("host")
        or body.get("host_id")
        or body.get("target")
        or "unknown"
    )
    source_ip = body.get("source_ip") or body.get("src_ip") or body.get("src") or body.get("attacker_ip") or ""
    destination = body.get("destination") or body.get("dst") or body.get("dest") or ""
    event_type = (
        body.get("event_type")
        or body.get("event")
        or body.get("alert_type")
        or body.get("alert")
        or body.get("anomaly_type")
        or "unknown"
    )
    severity = str(body.get("severity") or body.get("priority") or "medium").lower()
    raw_message = body.get("raw_message") or body.get("message") or body.get("description") or str(event_type)
    indicators = body.get("indicators") or {}
    if isinstance(indicators, list):
        indicators = {"items": indicators}
    evidence = body.get("evidence") or {}
    if not evidence and body.get("evidence_window"):
        evidence = dict(body["evidence_window"])
    confidence = float(body.get("confidence", body.get("anomaly_score", 0.5) / 100.0 if body.get("anomaly_score") else 0.5))
    if confidence > 1.0:
        confidence = round(confidence / 100.0, 4)
    scenario = body.get("scenario") or body.get("scenario_hint") or body.get("scenario_id")
    correlation_key = body.get("correlation_key") or _build_correlation_key(
        source_type, str(asset_id), str(source_ip), str(event_type)
    )

    return NormalizedThreatEvent(
        event_id=event_id,
        source_type=source_type,
        source_name=str(source_name),
        timestamp=timestamp,
        asset_id=str(asset_id),
        source_ip=str(source_ip),
        destination=str(destination),
        event_type=str(event_type),
        severity=severity,
        raw_message=str(raw_message),
        indicators=indicators,
        evidence=evidence,
        confidence=confidence,
        scenario=scenario,
        correlation_key=correlation_key,
        raw_event=raw_event,
        demo_synthetic=bool(body.get("demo_synthetic", body.get("synthetic", True))),
    )


def normalize_ingest_payload(body: Union[Dict[str, Any], List[Dict[str, Any]]]) -> List[NormalizedThreatEvent]:
    """
    Accept one event, a list of events, or wrapper objects with an events array.
    """
    if isinstance(body, list):
        return [normalize_raw_event(item) for item in body]

    if "events" in body and isinstance(body["events"], list):
        default_st = body.get("source_type")
        return [normalize_raw_event(ev, default_source_type=default_st) for ev in body["events"]]

    if "source_type" in body and any(k in body for k in ("event", "event_type", "alert", "anomaly_type")):
        return [normalize_raw_event(body)]

    if "events" not in body:
        return [normalize_raw_event(body)]

    return [normalize_raw_event(body)]


def events_share_time_window(events: List[NormalizedThreatEvent], window_seconds: float = 600.0) -> bool:
    """Return True if all event timestamps fall within window_seconds of each other."""
    parsed: List[datetime] = []
    for ev in events:
        try:
            ts = datetime.fromisoformat(ev.timestamp.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            parsed.append(ts)
        except (ValueError, TypeError):
            continue
    if len(parsed) < 2:
        return True
    span = (max(parsed) - min(parsed)).total_seconds()
    return span <= window_seconds
