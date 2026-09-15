"""Unit tests for MITRE ATT&CK Framework Mapping Engine."""

import pytest
from orchestrator.mitre_mapping import get_mitre_technique


def test_mitre_mapping_cryptominer():
    res = get_mitre_technique("cryptominer")
    assert res["technique_id"] == "T1496"
    assert res["technique_name"] == "Resource Hijacking"
    assert res["tactic"] == "Impact"


def test_mitre_mapping_port_scan():
    res = get_mitre_technique("port_scan")
    assert res["technique_id"] == "T1046"
    assert res["technique_name"] == "Network Service Discovery"
    assert res["tactic"] == "Discovery"


def test_mitre_mapping_c2_beacon():
    res = get_mitre_technique("c2_beacon")
    assert res["technique_id"] == "T1071"
    assert res["technique_name"] == "Application Layer Protocol"
    assert res["tactic"] == "Command and Control"


def test_mitre_mapping_worm():
    res = get_mitre_technique("worm")
    assert res["technique_id"] == "T1210"
    assert res["technique_name"] == "Exploitation of Remote Services"
    assert res["tactic"] == "Lateral Movement"


def test_mitre_mapping_aliases():
    res_crypto = get_mitre_technique("crypto_ransomware")
    assert res_crypto["technique_id"] == "T1496"

    res_scan = get_mitre_technique("syn_cytokine_flood")
    assert res_scan["technique_id"] == "T1046"

    res_c2 = get_mitre_technique("exfil_parasite")
    assert res_c2["technique_id"] == "T1071"

    res_worm_alias = get_mitre_technique("worm_ravage")
    assert res_worm_alias["technique_id"] == "T1210"

    res_kernel = get_mitre_technique("kernel_blight")
    assert res_kernel["technique_id"] == "T1210"


def test_mitre_mapping_unknown_and_empty():
    res_unknown = get_mitre_technique("some_unknown_attack_123")
    assert res_unknown["technique_id"] == "UNKNOWN"
    assert res_unknown["technique_name"] == "Unclassified"
    assert res_unknown["tactic"] == "Unknown"

    res_empty = get_mitre_technique("")
    assert res_empty["technique_id"] == "UNKNOWN"

    res_none = get_mitre_technique(None)
    assert res_none["technique_id"] == "UNKNOWN"
