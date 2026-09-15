"""Unit tests for Bottom Line Up Front (BLUF) Incident Summaries."""

import pytest
from orchestrator.bluf import generate_bluf_summary
from orchestrator.antibody import generate_antibody
from orchestrator.mitre_mapping import get_mitre_technique


@pytest.mark.parametrize("attack_type,expected_tech_id,expected_action", [
    ("cryptominer", "T1496", "terminate_process_and_isolate"),
    ("port_scan", "T1046", "drop_network_egress"),
    ("c2_beacon", "T1071", "sever_socket_connection"),
    ("worm", "T1210", "quarantine_source"),
])
def test_bluf_summary_all_attack_types(attack_type, expected_tech_id, expected_action):
    feature_vec = {"scenario": attack_type, "cpu": 90.0}
    det_rule = {"type": "scenario", "threshold": 0.9}
    action = {"type": expected_action}
    ab = generate_antibody(feature_vec, attack_type, 0.98, det_rule, action)

    incident = {
        "incident_id": f"inc-{attack_type}-1",
        "node_id": "node-beta",
        "attack_type": attack_type,
        "status": "quarantined",
        "confidence": 0.98,
        "detected_at": "2026-09-15T12:00:00+00:00",
        "owner_id": "admin_infra_1",
    }

    summary = generate_bluf_summary(incident, ab, total_nodes=8, immunized_count=7)

    assert isinstance(summary, str)
    assert len(summary) > 0

    # Validate required sections and key fields
    assert "BOTTOM LINE: Node node-beta compromised by " in summary
    assert "quarantined" in summary
    assert "Confidence: 98%" in summary
    assert expected_action in summary
    assert "DETAILS:" in summary
    assert "- Detection time: 2026-09-15T12:00:00+00:00" in summary
    assert f"- MITRE ATT&CK: {expected_tech_id}" in summary
    assert "- Affected node owner: admin_infra_1" in summary
    assert "- Recommended hardening:" in summary
    assert "- Network-wide immunity status: 7/8 nodes protected" in summary


def test_bluf_summary_default_fallback():
    incident = {
        "node_id": "node-unknown",
        "attack_type": "unclassified_anomaly",
        "status": "investigating",
        "confidence": 0.75,
    }
    summary = generate_bluf_summary(incident, None)

    assert "BOTTOM LINE: Node node-unknown compromised by unclassified_anomaly — investigating." in summary
    assert "Confidence: 75%." in summary
    assert "MITRE ATT&CK: UNKNOWN — Unclassified (Unknown)" in summary
    assert "8/8 nodes protected" in summary
