"""
SQLite Persistence Engine for IMMUNE-NET Orchestrator.
Persists immune memory, digital antibodies, confirmed threat history,
agent acknowledgements, and cryptographic audit trails with automated connection lifecycle management.
"""

import sqlite3
import json
import os
import logging
from typing import List, Optional, Dict, Any, Generator
from contextlib import contextmanager
from common.schemas import (
    Antibody,
    ConfirmedThreat,
    AgentAcknowledgement,
    AntibodySignature,
    NormalizedThreatEvent,
    PipelineIncidentRecord,
)
from orchestrator.mitre_mapping import get_mitre_technique

logger = logging.getLogger("orchestrator.database")
DB_PATH = os.getenv("IMMUNE_DB_PATH", "immune_memory.db")


class ImmuneDatabase:
    """SQLite-backed persistent store for antibodies, threats, acknowledgements, and audit logs."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.init_db()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager yielding a SQLite connection and ensuring deterministic closing."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """Initialize database schema with versioning and automatic migration."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Schema versioning table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Antibodies table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS antibodies (
                    antibody_id TEXT PRIMARY KEY,
                    schema_version INTEGER DEFAULT 1,
                    threat_type TEXT NOT NULL,
                    signature_json TEXT NOT NULL,
                    detection_rule TEXT NOT NULL,
                    neutralization_action TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    source_threat_id TEXT NOT NULL,
                    model_version TEXT DEFAULT 'detector-v1',
                    version INTEGER DEFAULT 1,
                    issuer TEXT DEFAULT 'immune-net-orchestrator',
                    signature_algorithm TEXT DEFAULT 'hmac-sha256',
                    digital_signature TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    neutralized_count INTEGER DEFAULT 0,
                    ebpf_rule TEXT,
                    recommendation TEXT,
                    mitre_json TEXT
                )
            """)

            # Ensure columns exist if table existed before
            columns = {row[1] for row in cursor.execute("PRAGMA table_info(antibodies)").fetchall()}
            if "recommendation" not in columns:
                cursor.execute("ALTER TABLE antibodies ADD COLUMN recommendation TEXT")
            if "mitre_json" not in columns:
                cursor.execute("ALTER TABLE antibodies ADD COLUMN mitre_json TEXT")
            if "synthesized_at" not in columns:
                cursor.execute("ALTER TABLE antibodies ADD COLUMN synthesized_at TEXT")
            if "half_life_hours" not in columns:
                cursor.execute("ALTER TABLE antibodies ADD COLUMN half_life_hours REAL DEFAULT 72.0")
            if "base_confidence" not in columns:
                cursor.execute("ALTER TABLE antibodies ADD COLUMN base_confidence REAL DEFAULT 1.0")

            # Threats table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    threat_id TEXT PRIMARY KEY,
                    schema_version INTEGER DEFAULT 1,
                    classification TEXT NOT NULL,
                    affected_agent TEXT NOT NULL,
                    peer_agents_json TEXT,
                    confidence_score REAL NOT NULL,
                    confidence_threshold REAL DEFAULT 0.85,
                    evidence_event_ids_json TEXT,
                    detection_model_or_rule_version TEXT,
                    confirmed_at TEXT NOT NULL,
                    recommended_neutralization_action TEXT,
                    correlation_id TEXT NOT NULL,
                    scenario_type TEXT,
                    narrative TEXT,
                    biomarkers_json TEXT,
                    mitre_json TEXT,
                    bluf_summary TEXT,
                    explanation_json TEXT
                )
            """)

            threat_columns = {row[1] for row in cursor.execute("PRAGMA table_info(threats)").fetchall()}
            if "mitre_json" not in threat_columns:
                cursor.execute("ALTER TABLE threats ADD COLUMN mitre_json TEXT")
            if "bluf_summary" not in threat_columns:
                cursor.execute("ALTER TABLE threats ADD COLUMN bluf_summary TEXT")
            if "explanation_json" not in threat_columns:
                cursor.execute("ALTER TABLE threats ADD COLUMN explanation_json TEXT")

            # Agent Acknowledgements table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_acknowledgements (
                    ack_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details TEXT
                )
            """)

            # Audit events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    agent_id TEXT,
                    correlation_id TEXT,
                    details_json TEXT
                )
            """)

            # Honeypot decoy attack capture table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS honeypot_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    attack_vector TEXT NOT NULL,
                    raw_payload TEXT,
                    antibody_id TEXT,
                    status TEXT DEFAULT 'captured'
                )
            """)

            # Normalized multi-source threat events (pipeline ingestion)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS normalized_events (
                    event_id TEXT PRIMARY KEY,
                    source_type TEXT NOT NULL,
                    source_name TEXT,
                    timestamp TEXT NOT NULL,
                    asset_id TEXT,
                    source_ip TEXT,
                    destination TEXT,
                    event_type TEXT,
                    severity TEXT,
                    raw_message TEXT,
                    indicators_json TEXT,
                    evidence_json TEXT,
                    confidence REAL,
                    scenario TEXT,
                    correlation_key TEXT,
                    raw_event_json TEXT,
                    demo_synthetic INTEGER DEFAULT 1,
                    ingested_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Pipeline incidents (correlation + triage + priority)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS pipeline_incidents (
                    incident_id TEXT PRIMARY KEY,
                    correlation_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    correlated_event_ids_json TEXT,
                    source_types_json TEXT,
                    correlation_score REAL,
                    confidence_score REAL,
                    evidence_count INTEGER,
                    classification TEXT,
                    classification_reason TEXT,
                    rule_version TEXT,
                    priority_score INTEGER,
                    priority_level TEXT,
                    priority_reason TEXT,
                    scenario_type TEXT,
                    mitre_json TEXT,
                    bluf_json TEXT,
                    blast_radius_json TEXT,
                    audit_json TEXT
                )
            """)

            # Set initial schema migration version
            cursor.execute("INSERT OR IGNORE INTO schema_migrations (version) VALUES (1)")
            cursor.execute("INSERT OR IGNORE INTO schema_migrations (version) VALUES (2)")
            conn.commit()

    # ---------------------------------------------------------
    # Antibodies
    # ---------------------------------------------------------
    def save_antibody(self, antibody: Antibody) -> bool:
        """
        Insert or update a digital antibody record.

        Args:
            antibody: Antibody model instance.

        Returns:
            True on successful persistence.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            sig_json = json.dumps(antibody.signature.model_dump())
            mitre_json = json.dumps(antibody.mitre if antibody.mitre else get_mitre_technique(antibody.threat_type))
            cursor.execute("""
                INSERT INTO antibodies (
                    antibody_id, schema_version, threat_type, signature_json,
                    detection_rule, neutralization_action, created_at,
                    source_threat_id, model_version, version, issuer,
                    signature_algorithm, digital_signature, status,
                    neutralized_count, ebpf_rule, recommendation, mitre_json,
                    synthesized_at, half_life_hours, base_confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(antibody_id) DO UPDATE SET
                    status=excluded.status,
                    version=excluded.version,
                    neutralized_count=excluded.neutralized_count,
                    mitre_json=excluded.mitre_json,
                    recommendation=excluded.recommendation,
                    synthesized_at=excluded.synthesized_at,
                    half_life_hours=excluded.half_life_hours,
                    base_confidence=excluded.base_confidence
            """, (
                antibody.antibody_id,
                antibody.schema_version,
                antibody.threat_type,
                sig_json,
                antibody.detection_rule,
                antibody.neutralization_action,
                antibody.created_at,
                antibody.source_threat_id,
                antibody.model_version,
                antibody.version,
                antibody.issuer,
                antibody.signature_algorithm,
                antibody.digital_signature,
                antibody.status,
                antibody.neutralized_count,
                antibody.ebpf_rule,
                antibody.recommendation or "",
                mitre_json,
                antibody.synthesized_at.isoformat() if hasattr(antibody, "synthesized_at") else antibody.created_at,
                antibody.half_life_hours,
                antibody.base_confidence,
            ))
            conn.commit()
            logger.info(f"[DB SAVED] Persisted digital antibody {antibody.antibody_id} ({antibody.threat_type})")
            return True

    def get_antibody(self, antibody_id: str) -> Optional[Antibody]:
        """
        Fetch single antibody by ID.

        Args:
            antibody_id: Antibody identifier.

        Returns:
            Antibody model instance or None.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM antibodies WHERE antibody_id = ?", (antibody_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_antibody(row)

    def get_all_antibodies(self, status: Optional[str] = None) -> List[Antibody]:
        """
        Retrieve all antibodies, optionally filtered by status.

        Args:
            status: Optional filter ('active', 'revoked', 'superseded').

        Returns:
            List of Antibody model instances.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute("SELECT * FROM antibodies WHERE status = ? ORDER BY created_at DESC", (status,))
            else:
                cursor.execute("SELECT * FROM antibodies ORDER BY created_at DESC")
            rows = cursor.fetchall()
            return [self._row_to_antibody(r) for r in rows]

    def increment_antibody_neutralization(self, antibody_id: str) -> None:
        """
        Increment the counter of repeat attacks neutralized by this antibody.

        Args:
            antibody_id: Antibody identifier.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE antibodies SET neutralized_count = neutralized_count + 1 WHERE antibody_id = ?", (antibody_id,))
            conn.commit()

    def _row_to_antibody(self, row: sqlite3.Row) -> Antibody:
        from datetime import datetime as _dt
        from datetime import timezone as _tz

        sig_data = json.loads(row["signature_json"])
        signature = AntibodySignature(**sig_data)
        mitre_data = None
        if "mitre_json" in row.keys() and row["mitre_json"]:
            try:
                mitre_data = json.loads(row["mitre_json"])
            except Exception:
                mitre_data = None
        if not mitre_data:
            mitre_data = get_mitre_technique(row["threat_type"])

        rec = row["recommendation"] if "recommendation" in row.keys() else None

        synthesized_at = None
        if "synthesized_at" in row.keys() and row["synthesized_at"]:
            try:
                synthesized_at = _dt.fromisoformat(row["synthesized_at"].replace("Z", "+00:00"))
            except (ValueError, TypeError):
                synthesized_at = None

        half_life = row["half_life_hours"] if "half_life_hours" in row.keys() and row["half_life_hours"] is not None else 72.0
        base_conf = row["base_confidence"] if "base_confidence" in row.keys() and row["base_confidence"] is not None else 1.0

        return Antibody(
            antibody_id=row["antibody_id"],
            schema_version=row["schema_version"],
            threat_type=row["threat_type"],
            signature=signature,
            detection_rule=row["detection_rule"],
            neutralization_action=row["neutralization_action"],
            created_at=row["created_at"],
            source_threat_id=row["source_threat_id"],
            model_version=row["model_version"],
            version=row["version"],
            issuer=row["issuer"],
            signature_algorithm=row["signature_algorithm"],
            digital_signature=row["digital_signature"],
            status=row["status"],
            neutralized_count=row["neutralized_count"],
            ebpf_rule=row["ebpf_rule"] or "",
            recommendation=rec,
            mitre=mitre_data,
            synthesized_at=synthesized_at or _dt.now(_tz.utc),
            half_life_hours=half_life,
            base_confidence=base_conf,
        )

    # ---------------------------------------------------------
    # Threats
    # ---------------------------------------------------------
    def save_threat(self, threat: ConfirmedThreat) -> bool:
        """
        Insert confirmed threat record.

        Args:
            threat: ConfirmedThreat instance.

        Returns:
            True on successful persistence.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            mitre_json = json.dumps(threat.mitre if threat.mitre else get_mitre_technique(threat.scenario_type))
            cursor.execute("""
                INSERT OR REPLACE INTO threats (
                    threat_id, schema_version, classification, affected_agent,
                    peer_agents_json, confidence_score, confidence_threshold,
                    evidence_event_ids_json, detection_model_or_rule_version,
                    confirmed_at, recommended_neutralization_action, correlation_id,
                    scenario_type, narrative, biomarkers_json, mitre_json, bluf_summary,
                    explanation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                threat.threat_id,
                threat.schema_version,
                threat.classification,
                threat.affected_agent,
                json.dumps(threat.peer_agents),
                threat.confidence_score,
                threat.confidence_threshold,
                json.dumps(threat.evidence_event_ids),
                threat.detection_model_or_rule_version,
                threat.confirmed_at,
                threat.recommended_neutralization_action,
                threat.correlation_id,
                threat.scenario_type,
                threat.narrative or "",
                json.dumps(threat.biomarkers),
                mitre_json,
                threat.bluf_summary or "",
                json.dumps(threat.explanation) if threat.explanation else None,
            ))
            conn.commit()
            logger.info(f"[DB SAVED] Persisted confirmed threat {threat.threat_id} on {threat.affected_agent}")
            return True

    def get_threats(self, limit: int = 50) -> List[ConfirmedThreat]:
        """
        Fetch list of confirmed threats ordered by timestamp descending.

        Args:
            limit: Maximum count to return.

        Returns:
            List of ConfirmedThreat model instances.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM threats ORDER BY confirmed_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                mitre_data = None
                if "mitre_json" in row.keys() and row["mitre_json"]:
                    try:
                        mitre_data = json.loads(row["mitre_json"])
                    except Exception:
                        mitre_data = None
                if not mitre_data:
                    mitre_data = get_mitre_technique(row["scenario_type"])

                bluf = row["bluf_summary"] if "bluf_summary" in row.keys() else None

                explanation_data = None
                if "explanation_json" in row.keys() and row["explanation_json"]:
                    try:
                        explanation_data = json.loads(row["explanation_json"])
                    except Exception:
                        explanation_data = None

                results.append(ConfirmedThreat(
                    threat_id=row["threat_id"],
                    schema_version=row["schema_version"],
                    classification=row["classification"],
                    affected_agent=row["affected_agent"],
                    peer_agents=json.loads(row["peer_agents_json"] or "[]"),
                    confidence_score=row["confidence_score"],
                    confidence_threshold=row["confidence_threshold"],
                    evidence_event_ids=json.loads(row["evidence_event_ids_json"] or "[]"),
                    detection_model_or_rule_version=row["detection_model_or_rule_version"],
                    confirmed_at=row["confirmed_at"],
                    recommended_neutralization_action=row["recommended_neutralization_action"],
                    correlation_id=row["correlation_id"],
                    scenario_type=row["scenario_type"],
                    narrative=row["narrative"],
                    biomarkers=json.loads(row["biomarkers_json"] or "{}"),
                    mitre=mitre_data,
                    bluf_summary=bluf,
                    explanation=explanation_data,
                ))
            return results

    # ---------------------------------------------------------
    # Acknowledgements
    # ---------------------------------------------------------
    def save_acknowledgement(self, ack: AgentAcknowledgement) -> bool:
        """
        Record agent acknowledgement.

        Args:
            ack: AgentAcknowledgement instance.

        Returns:
            True on successful persistence.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO agent_acknowledgements (
                    ack_id, agent_id, target_id, type, status, timestamp, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                ack.ack_id,
                ack.agent_id,
                ack.target_id,
                ack.type,
                ack.status,
                ack.timestamp,
                ack.details or "",
            ))
            conn.commit()
            return True

    def get_acknowledgements_for_target(self, target_id: str) -> List[AgentAcknowledgement]:
        """
        Fetch all agent receipts for an antibody or command.

        Args:
            target_id: Antibody or command identifier.

        Returns:
            List of AgentAcknowledgement records.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agent_acknowledgements WHERE target_id = ?", (target_id,))
            rows = cursor.fetchall()
            return [AgentAcknowledgement(**dict(r)) for r in rows]

    # ---------------------------------------------------------
    # Audit Events
    # ---------------------------------------------------------
    def log_audit(
        self,
        event_type: str,
        agent_id: Optional[str],
        correlation_id: Optional[str],
        details: Dict[str, Any],
        event_id: Optional[str] = None,
    ) -> None:
        """
        Append an audit event log.

        Args:
            event_type: Audit action name.
            agent_id: Involved agent ID.
            correlation_id: Tracking correlation ID.
            details: Payload dictionary.
            event_id: Optional unique event ID.
        """
        from common.schemas import generate_uuid, utc_iso_now
        eid = event_id or generate_uuid("audit-")
        now = utc_iso_now()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_events (event_id, timestamp, event_type, agent_id, correlation_id, details_json)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (eid, now, event_type, agent_id or "", correlation_id or "", json.dumps(details)))
            conn.commit()

    def get_audit_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve recent audit events.

        Args:
            limit: Maximum count to return.

        Returns:
            List of audit event dictionaries.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            res = []
            for r in rows:
                item = dict(r)
                item["details"] = json.loads(item["details_json"])
                res.append(item)
            return res

    # ---------------------------------------------------------
    # Honeypot Events
    # ---------------------------------------------------------
    def save_honeypot_event(
        self,
        source_ip: str,
        attack_vector: str,
        raw_payload: Dict[str, Any],
        antibody_id: Optional[str] = None,
        event_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> bool:
        """
        Persist a captured honeypot decoy attack event.

        Args:
            source_ip: Originating attacker IP address.
            attack_vector: Detected attack classification.
            raw_payload: Full captured telemetry payload.
            antibody_id: Optional triggered antibody ID.
            event_id: Optional unique event identifier.
            timestamp: Optional ISO 8601 timestamp.

        Returns:
            True on successful persistence.
        """
        from common.schemas import utc_iso_now, generate_uuid
        now = timestamp or utc_iso_now()
        eid = event_id or generate_uuid("hp-")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO honeypot_events (event_id, timestamp, source_ip, attack_vector, raw_payload, antibody_id, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                eid,
                now,
                source_ip,
                attack_vector,
                json.dumps(raw_payload),
                antibody_id or "",
                "captured",
            ))
            conn.commit()
            logger.info(f"[HONEYPOT] Captured attack '{attack_vector}' from {source_ip} (event {eid})")
            return True

    def get_honeypot_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieve recent honeypot capture events ordered by timestamp descending.

        Args:
            limit: Maximum count to return.

        Returns:
            List of event dictionaries.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM honeypot_events ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
        events = []
        for r in rows:
            item = dict(r)
            try:
                item["raw_payload"] = json.loads(item["raw_payload"] or "{}")
            except Exception:
                item["raw_payload"] = {}
            events.append(item)
        return events

    # ---------------------------------------------------------
    # Reset for Demo
    # ---------------------------------------------------------
    def reset_simulation(self) -> None:
        """Explicit demo reset: clears simulation tables."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM antibodies")
            cursor.execute("DELETE FROM threats")
            cursor.execute("DELETE FROM agent_acknowledgements")
            cursor.execute("DELETE FROM audit_events")
            cursor.execute("DELETE FROM honeypot_events")
            cursor.execute("DELETE FROM normalized_events")
            cursor.execute("DELETE FROM pipeline_incidents")
            conn.commit()
            logger.info("[DB RESET] Simulation tables cleared.")

    # ---------------------------------------------------------
    # Normalized events & pipeline incidents
    # ---------------------------------------------------------
    def save_normalized_event(self, event: NormalizedThreatEvent) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO normalized_events (
                    event_id, source_type, source_name, timestamp, asset_id, source_ip,
                    destination, event_type, severity, raw_message, indicators_json,
                    evidence_json, confidence, scenario, correlation_key, raw_event_json, demo_synthetic
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.source_type,
                event.source_name,
                event.timestamp,
                event.asset_id,
                event.source_ip,
                event.destination,
                event.event_type,
                event.severity,
                event.raw_message,
                json.dumps(event.indicators),
                json.dumps(event.evidence),
                event.confidence,
                event.scenario,
                event.correlation_key,
                json.dumps(event.raw_event),
                1 if event.demo_synthetic else 0,
            ))
            conn.commit()
            return True

    def get_normalized_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM normalized_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["indicators"] = json.loads(item.pop("indicators_json") or "{}")
            item["evidence"] = json.loads(item.pop("evidence_json") or "{}")
            item["raw_event"] = json.loads(item.pop("raw_event_json") or "{}")
            item["demo_synthetic"] = bool(item.get("demo_synthetic"))
            out.append(item)
        return out

    def save_pipeline_incident(self, record: PipelineIncidentRecord) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO pipeline_incidents (
                    incident_id, correlation_id, created_at, correlated_event_ids_json,
                    source_types_json, correlation_score, confidence_score, evidence_count,
                    classification, classification_reason, rule_version, priority_score,
                    priority_level, priority_reason, scenario_type, mitre_json, bluf_json,
                    blast_radius_json, audit_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.incident_id,
                record.correlation_id,
                record.created_at,
                json.dumps(record.correlated_event_ids),
                json.dumps(record.source_types),
                record.correlation_score,
                record.confidence_score,
                record.evidence_count,
                record.classification,
                record.classification_reason,
                record.rule_version,
                record.priority_score,
                record.priority_level,
                record.priority_reason,
                record.scenario_type,
                json.dumps(record.mitre),
                json.dumps(record.bluf),
                json.dumps(record.blast_radius or {}),
                json.dumps(record.audit),
            ))
            conn.commit()
            return True

    def get_pipeline_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM pipeline_incidents ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            rows = cursor.fetchall()
        return [self._row_to_pipeline_incident(r) for r in rows]

    def get_pipeline_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM pipeline_incidents WHERE incident_id = ?", (incident_id,))
            row = cursor.fetchone()
        if not row:
            return None
        return self._row_to_pipeline_incident(row)

    def _row_to_pipeline_incident(self, row: sqlite3.Row) -> Dict[str, Any]:
        item = dict(row)
        item["correlated_event_ids"] = json.loads(item.pop("correlated_event_ids_json") or "[]")
        item["source_types"] = json.loads(item.pop("source_types_json") or "[]")
        item["mitre"] = json.loads(item.pop("mitre_json") or "{}")
        item["bluf"] = json.loads(item.pop("bluf_json") or "{}")
        item["blast_radius"] = json.loads(item.pop("blast_radius_json") or "{}")
        item["audit"] = json.loads(item.pop("audit_json") or "{}")
        return item
