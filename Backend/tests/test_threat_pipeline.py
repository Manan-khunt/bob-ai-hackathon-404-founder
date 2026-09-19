"""Tests for multi-source threat ingestion pipeline."""

import asyncio
import os
import tempfile

import pytest
from httpx import ASGITransport, AsyncClient

from orchestrator.database import ImmuneDatabase
from orchestrator.detector import AdaptiveCorrelator
from orchestrator.pipeline import ThreatPipeline
from orchestrator.normalization import normalize_raw_event, normalize_ingest_payload
from orchestrator.mitre_mapping import get_mitre_technique
from orchestrator.demo_scenarios import get_demo_scenario


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = ImmuneDatabase(db_path=path)
    yield db
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def pipeline(temp_db):
    return ThreatPipeline(AdaptiveCorrelator(), temp_db)


def test_siem_event_normalization():
    raw = {"timestamp": "2026-01-01T00:00:00+00:00", "src_ip": "1.2.3.4", "event": "port_scan", "host": "node-beta"}
    ev = normalize_raw_event(raw)
    assert ev.source_type == "SIEM"
    assert ev.event_type == "port_scan"
    assert ev.source_ip == "1.2.3.4"
    assert ev.asset_id == "node-beta"
    assert ev.raw_event == raw


def test_ingest_list_normalization():
    events = normalize_ingest_payload([{"source_type": "HONEYPOT", "attack_vector": "probe", "attacker_ip": "9.9.9.9"}])
    assert len(events) == 1
    assert events[0].source_type == "HONEYPOT"


def test_coordinated_intrusion_true_threat(pipeline):
    result = asyncio.run(pipeline.run_demo_scenario("coordinated_intrusion", auto_respond=False))
    assert result["ingested_events"] == 4
    assert result["correlated_incident"] is True
    assert result["classification"] == "TRUE_THREAT"
    assert result["confidence"] == 0.96
    assert result["priority_score"] == 96
    assert result["priority_level"] == "CRITICAL"
    assert result["mitre"]["technique_id"] == "T1046"
    assert "bottom_line" in result["bluf"]
    assert result["bluf"]["mitre"]["technique_id"] == "T1046"


def test_benign_noise_false_positive(pipeline):
    result = asyncio.run(pipeline.run_demo_scenario("benign_noise", auto_respond=False))
    assert result["classification"] == "FALSE_POSITIVE"
    assert result["priority_score"] <= 25


def test_needs_review_classification(pipeline):
    result = asyncio.run(pipeline.run_demo_scenario("needs_review", auto_respond=False))
    assert result["classification"] == "NEEDS_REVIEW"


def test_multi_source_correlation_scores(pipeline):
    raw = get_demo_scenario("coordinated_intrusion")
    events = normalize_ingest_payload(raw)
    corr = pipeline.correlator.correlate_normalized_events(events)
    assert corr["correlation_score"] >= 0.5
    assert len(corr["correlated_event_ids"]) == 4


def test_mitre_mapping_not_invented():
    mitre = get_mitre_technique("port_scan")
    assert mitre["technique_id"] == "T1046"
    assert mitre["technique_name"] == "Network Service Discovery"


def test_bluf_structure(pipeline):
    result = asyncio.run(pipeline.run_demo_scenario("coordinated_intrusion", auto_respond=False))
    bluf = result["bluf"]
    for key in ("bottom_line", "impact", "evidence", "mitre", "priority", "recommended_action"):
        assert key in bluf


def test_demo_end_to_end_with_response(pipeline):
    result = asyncio.run(pipeline.run_demo_scenario("coordinated_intrusion", auto_respond=False))
    assert result["audit"]["source_list"]
    assert result["audit"]["event_ids"]


def test_backward_compat_adaptive_correlator_cryptominer():
    from common.schemas import LocalAnomalyEvent
    from orchestrator.detector import AdaptiveCorrelator

    correlator = AdaptiveCorrelator()
    anomaly = LocalAnomalyEvent(
        agent_id="node-beta",
        score=94.0,
        threshold=70.0,
        feature_names=["cpu_percent", "entropy"],
        evidence_window={"cpu_percent": 88.0, "entropy": 0.92, "process": "xmrig"},
        scenario_hint="cryptominer",
    )
    threat = correlator.ingest_anomaly(anomaly)
    assert threat is not None
    assert threat.scenario_type == "cryptominer"


def test_priority_scoring_deterministic(pipeline):
    result = asyncio.run(pipeline.run_demo_scenario("coordinated_intrusion", auto_respond=False))
    assert 0 <= result["priority_score"] <= 100
    assert result["priority_level"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert result["priority_reason"] != ""
    assert result["priority_score"] >= 90
    assert result["priority_level"] == "CRITICAL"


def test_priority_scoring_low_for_false_positive(pipeline):
    result = asyncio.run(pipeline.run_demo_scenario("benign_noise", auto_respond=False))
    assert result["priority_score"] <= 25
    assert result["priority_level"] == "LOW"


def test_mitre_mapping_all_attack_types():
    for attack_type, expected_id in [
        ("cryptominer", "T1496"),
        ("port_scan", "T1046"),
        ("c2_beacon", "T1071"),
        ("worm", "T1210"),
    ]:
        mitre = get_mitre_technique(attack_type)
        assert mitre["technique_id"] == expected_id
        assert mitre["technique_name"] != "Unclassified"
        assert mitre["tactic"] != "Unknown"


def test_mitre_mapping_unknown_returns_unknown():
    mitre = get_mitre_technique("nonexistent_attack")
    assert mitre["technique_id"] == "UNKNOWN"
    assert mitre["technique_name"] == "Unclassified"
    assert mitre["tactic"] == "Unknown"


def test_mitre_enriched_includes_confidence_and_evidence(pipeline):
    result = asyncio.run(pipeline.run_demo_scenario("coordinated_intrusion", auto_respond=False))
    mitre = result["mitre"]
    assert "confidence" in mitre
    assert "evidence" in mitre
    assert isinstance(mitre["confidence"], float)
    assert isinstance(mitre["evidence"], list)
    assert len(mitre["evidence"]) > 0


def test_bluf_structure_full(pipeline):
    result = asyncio.run(pipeline.run_demo_scenario("coordinated_intrusion", auto_respond=False))
    bluf = result["bluf"]
    for key in ("bottom_line", "impact", "evidence", "mitre", "priority", "recommended_action"):
        assert key in bluf, f"Missing BLUF key: {key}"
    assert isinstance(bluf["bottom_line"], str)
    assert len(bluf["bottom_line"]) > 0
    assert isinstance(bluf["impact"], str)
    assert isinstance(bluf["evidence"], list)
    assert isinstance(bluf["mitre"], dict)
    assert isinstance(bluf["priority"], dict)
    assert "score" in bluf["priority"]
    assert "level" in bluf["priority"]
    assert isinstance(bluf["recommended_action"], str)


def test_all_source_types_normalize():
    sources = [
        ({"source_type": "SIEM", "src_ip": "1.1.1.1", "event": "alert"}, "SIEM"),
        ({"source_type": "CYBER_SENSOR", "sensor_id": "s1", "alert_type": "spike"}, "CYBER_SENSOR"),
        ({"source_type": "SATELLITE", "observation_type": "recon"}, "SATELLITE"),
        ({"source_type": "INTELLIGENCE_REPORT", "report_type": "apt"}, "INTELLIGENCE_REPORT"),
        ({"source_type": "HONEYPOT", "attack_vector": "probe", "attacker_ip": "2.2.2.2"}, "HONEYPOT"),
        ({"source_type": "ENDPOINT", "agent_id": "node-a", "anomaly_type": "process_anomaly"}, "ENDPOINT"),
        ({"source_type": "NETWORK_SENSOR", "alert": "spike", "src": "3.3.3.3", "dst": "4.4.4.4"}, "NETWORK_SENSOR"),
    ]
    for raw, expected_type in sources:
        ev = normalize_raw_event(raw)
        assert ev.source_type == expected_type, f"Source type mismatch for {expected_type}"
        assert ev.raw_event == raw, f"raw_event not preserved for {expected_type}"


def test_triage_deterministic_thresholds():
    from orchestrator.triage import classify_triage
    events = []

    result = classify_triage(
        correlation_score=0.9, confidence_score=0.95,
        evidence_count=5, source_count=4, events=events,
    )
    assert result["classification"] == "TRUE_THREAT"
    assert result["rule_version"] == "triage-deterministic-v1"

    result = classify_triage(
        correlation_score=0.2, confidence_score=0.3,
        evidence_count=1, source_count=1, events=events,
    )
    assert result["classification"] == "FALSE_POSITIVE"

    result = classify_triage(
        correlation_score=0.55, confidence_score=0.65,
        evidence_count=2, source_count=2, events=events,
    )
    assert result["classification"] == "NEEDS_REVIEW"


def test_backward_compat_port_scan():
    from common.schemas import LocalAnomalyEvent
    correlator = AdaptiveCorrelator()
    anomaly = LocalAnomalyEvent(
        agent_id="node-beta", score=92.0, threshold=70.0,
        feature_names=["connection_rate", "network_connections"],
        evidence_window={"connection_rate": 22.0, "network_connections": 120, "process": "syn_scan"},
        scenario_hint="port_scan",
    )
    threat = correlator.ingest_anomaly(anomaly)
    assert threat is not None
    assert threat.scenario_type == "port_scan"
    assert threat.mitre["technique_id"] == "T1046"


def test_backward_compat_c2_beacon():
    from common.schemas import LocalAnomalyEvent
    correlator = AdaptiveCorrelator()
    anomaly = LocalAnomalyEvent(
        agent_id="node-beta", score=90.0, threshold=70.0,
        feature_names=["destination", "entropy"],
        evidence_window={"destination": "evil-c2.example.com:443", "entropy": 0.88, "process": "beacon_agent"},
        scenario_hint="c2_beacon",
    )
    threat = correlator.ingest_anomaly(anomaly)
    assert threat is not None
    assert threat.scenario_type == "c2_beacon"
    assert threat.mitre["technique_id"] == "T1071"


def test_backward_compat_worm():
    from common.schemas import LocalAnomalyEvent
    correlator = AdaptiveCorrelator()
    anomaly = LocalAnomalyEvent(
        agent_id="node-beta", score=96.0, threshold=70.0,
        feature_names=["network_connections", "process"],
        evidence_window={"network_connections": 15, "process": "worm_spread", "destination": "10.0.1.5:445"},
        scenario_hint="worm",
    )
    threat = correlator.ingest_anomaly(anomaly)
    assert threat is not None
    assert threat.scenario_type == "worm"
    assert threat.mitre["technique_id"] == "T1210"


def test_audit_trail_complete(pipeline):
    result = asyncio.run(pipeline.run_demo_scenario("coordinated_intrusion", auto_respond=False))
    audit = result["audit"]
    assert "event_ids" in audit
    assert "correlation_id" in audit
    assert "incident_id" in audit
    assert "rule_version" in audit
    assert "triage_rule_version" in audit
    assert "pipeline_version" in audit
    assert "classification_reason" in audit
    assert "timestamp" in audit
    assert "source_list" in audit
    assert len(audit["source_list"]) > 0
    assert audit["demo_synthetic"] is True


def test_demo_threat_scenario_api():
    from orchestrator.app import app

    async def _call():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/api/demo/threat-scenario", json={"scenario": "coordinated_intrusion"})

    resp = asyncio.run(_call())
    assert resp.status_code == 200
    data = resp.json()
    assert data["scenario"] == "coordinated_intrusion"
    assert data["classification"] == "TRUE_THREAT"
    assert "bluf" in data
    assert data.get("containment") is not None or data.get("antibody") is not None


def test_ingest_events_api():
    from orchestrator.app import app

    async def _call():
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post("/api/ingest/events", json={
                "events": [
                    {"source_type": "SIEM", "src_ip": "10.0.0.99", "event": "port_scan", "host": "node-alpha"},
                    {"source_type": "HONEYPOT", "attacker_ip": "10.0.0.99", "attack_vector": "probe", "asset_id": "node-alpha"},
                ]
            })

    resp = asyncio.run(_call())
    assert resp.status_code == 200
    data = resp.json()
    assert data["ingested_events"] == 2
    assert "classification" in data
    assert "correlation" in data
