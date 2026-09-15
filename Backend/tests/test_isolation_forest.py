"""Unit tests for Innate Anomaly Detector (Isolation Forest)."""

import pytest
from common.schemas import TelemetryEvent
from agent.detector import InnateAnomalyDetector

def test_detector_baseline_normal():
    detector = InnateAnomalyDetector(agent_id="test-agent", threshold=70.0)
    normal_telem = TelemetryEvent(
        agent_id="test-agent",
        process="systemd",
        cpu_percent=18.0,
        memory_percent=35.0,
        network_connections=12,
        bytes_sent=1200,
        connection_rate=2.0,
        file_activity=5
    )
    score, event = detector.evaluate(normal_telem)
    # Normal telemetry should not trigger an anomaly
    assert score < 70.0
    assert event is None

def test_detector_flags_malicious_anomaly():
    detector = InnateAnomalyDetector(agent_id="test-agent", threshold=70.0)
    malicious_telem = TelemetryEvent(
        agent_id="test-agent",
        process="xmrig",
        cpu_percent=95.0,
        memory_percent=75.0,
        network_connections=35,
        bytes_sent=25000,
        connection_rate=12.0,
        file_activity=80,
        scenario_id="cryptominer",
        entropy=0.94
    )
    score, event = detector.evaluate(malicious_telem)
    assert score >= 70.0
    assert event is not None
    assert event.agent_id == "test-agent"
    assert event.evidence_window["cpu_percent"] == 95.0

def test_detector_handles_malformed_input():
    detector = InnateAnomalyDetector(agent_id="test-agent")
    # Missing required float values should not raise unhandled exception
    score, event = detector.evaluate(TelemetryEvent(agent_id="test-agent", cpu_percent=0.0))
    assert isinstance(score, float)
