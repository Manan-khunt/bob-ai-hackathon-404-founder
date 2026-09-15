"""Unit tests for SQLite Immune Memory Database."""

import pytest
import os
import gc
from common.schemas import ConfirmedThreat, Antibody, AntibodySignature, AgentAcknowledgement
from orchestrator.database import ImmuneDatabase

TEST_DB = "test_immune_memory.db"


@pytest.fixture
def db():
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass
    db_inst = ImmuneDatabase(db_path=TEST_DB)
    yield db_inst
    gc.collect()
    if os.path.exists(TEST_DB):
        try:
            os.remove(TEST_DB)
        except Exception:
            pass


def test_save_and_retrieve_antibody(db):
    ab = Antibody(
        antibody_id="AB-TEST-1",
        threat_type="cryptominer",
        signature=AntibodySignature(features=["cpu"], operator="and", thresholds={"cpu": 70}),
        detection_rule="block cpu > 70",
        neutralization_action="kill",
        source_threat_id="threat-1",
        digital_signature="sig-123",
        ebpf_rule="SEC(test) drop",
    )
    db.save_antibody(ab)

    retrieved = db.get_antibody("AB-TEST-1")
    assert retrieved is not None
    assert retrieved.antibody_id == "AB-TEST-1"
    assert retrieved.threat_type == "cryptominer"
    assert retrieved.signature.thresholds["cpu"] == 70
    assert retrieved.mitre["technique_id"] == "T1496"


def test_sqlite_restart_rehydration(db):
    # Save antibody
    ab = Antibody(
        antibody_id="AB-PERSIST-1",
        threat_type="port_scan",
        signature=AntibodySignature(features=["rate"], operator="and", thresholds={"rate": 20}),
        detection_rule="block scan",
        neutralization_action="drop",
        source_threat_id="threat-2",
        digital_signature="sig-456",
    )
    db.save_antibody(ab)

    # Re-instantiate database connection (simulating restart)
    new_db = ImmuneDatabase(db_path=TEST_DB)
    active_abs = new_db.get_all_antibodies(status="active")
    assert len(active_abs) == 1
    assert active_abs[0].antibody_id == "AB-PERSIST-1"
    assert active_abs[0].mitre["technique_id"] == "T1046"
