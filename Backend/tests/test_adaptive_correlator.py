"""Unit tests for Adaptive Threat Correlator."""

import pytest
from common.schemas import LocalAnomalyEvent, TelemetryEvent
from orchestrator.detector import AdaptiveCorrelator

def test_correlator_confirms_cryptominer():
    correlator = AdaptiveCorrelator()
    anomaly = LocalAnomalyEvent(
        agent_id="node-beta",
        score=94.0,
        threshold=70.0,
        feature_names=["cpu_percent", "entropy"],
        evidence_window={"cpu_percent": 88.0, "entropy": 0.92, "process": "xmrig"},
        scenario_hint="cryptominer"
    )
    threat = correlator.ingest_anomaly(anomaly)
    assert threat is not None
    assert threat.scenario_type == "cryptominer"
    assert threat.confidence_score >= 0.85
    assert threat.affected_agent == "node-beta"

def test_correlator_confirms_port_scan():
    correlator = AdaptiveCorrelator()
    anomaly = LocalAnomalyEvent(
        agent_id="node-alpha",
        score=91.0,
        threshold=70.0,
        feature_names=["connection_rate"],
        evidence_window={"connection_rate": 28.0, "network_connections": 110, "process": "syn_scan"},
        scenario_hint="port_scan"
    )
    threat = correlator.ingest_anomaly(anomaly)
    assert threat is not None
    assert threat.scenario_type == "port_scan"
    assert threat.confidence_score >= 0.85

def test_correlator_confirms_c2_beacon():
    correlator = AdaptiveCorrelator()
    anomaly = LocalAnomalyEvent(
        agent_id="node-gamma",
        score=89.0,
        threshold=70.0,
        feature_names=["destination", "entropy"],
        evidence_window={"destination": "evil-c2.bio.net:443", "entropy": 0.81, "process": "exfil_parasite"},
        scenario_hint="c2_beacon"
    )
    threat = correlator.ingest_anomaly(anomaly)
    assert threat is not None
    assert threat.scenario_type == "c2_beacon"

def test_correlator_confirms_worm():
    correlator = AdaptiveCorrelator()
    anomaly = LocalAnomalyEvent(
        agent_id="node-delta",
        score=96.0,
        threshold=70.0,
        feature_names=["destination", "network_connections"],
        evidence_window={"destination": "10.0.1.30:22", "network_connections": 55, "process": "worm_propagate"},
        scenario_hint="worm"
    )
    threat = correlator.ingest_anomaly(anomaly)
    assert threat is not None
    assert threat.scenario_type == "worm"
