"""
Phase Memory and Alert Storage for IMMUNE-NET.
Persists phase-specific digital antibodies, security incidents, alerts, and node quarantine state
in a lightweight SQLite database with automated transaction management.
"""

import json
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional, Generator
from contextlib import contextmanager


class PhaseMemory:
    """SQLite-backed persistent memory store for antibodies, incident records, and administrative alerts."""

    def __init__(self, db_path: str | Path = "data/immune_memory.db"):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield a configured SQLite connection and ensure deterministic closure on exit."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init(self) -> None:
        """Initialize database tables and schema migrations."""
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS phase_antibodies (antibody_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS phase_incidents (incident_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS phase_quarantines (agent_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS telemetry_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    message TEXT NOT NULL,
                    sent_at TEXT NOT NULL,
                    acknowledged_at TEXT,
                    escalated INTEGER NOT NULL DEFAULT 0,
                    channel TEXT NOT NULL,
                    attack_type TEXT
                );
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(alerts)")}
            if "attack_type" not in columns:
                db.execute("ALTER TABLE alerts ADD COLUMN attack_type TEXT")
            db.commit()

    def save_antibody(self, antibody: Dict[str, Any]) -> None:
        """
        Persist a digital antibody payload.

        Args:
            antibody: Antibody dictionary containing signature and rules.
        """
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO phase_antibodies VALUES (?, ?)", (antibody["antibody_id"], json.dumps(antibody)))
            db.commit()

    def list_antibodies(self) -> List[Dict[str, Any]]:
        """
        Retrieve all persisted digital antibodies.

        Returns:
            List of antibody payload dictionaries.
        """
        with self._connect() as db:
            return [json.loads(row["payload"]) for row in db.execute("SELECT payload FROM phase_antibodies")]

    def save_incident(self, incident: Dict[str, Any]) -> None:
        """
        Persist a confirmed security incident.

        Args:
            incident: Incident dictionary with metadata, MITRE mapping, and BLUF summary.
        """
        with self._connect() as db:
            db.execute("INSERT OR REPLACE INTO phase_incidents VALUES (?, ?)", (incident["incident_id"], json.dumps(incident)))
            db.commit()

    def list_incidents(self) -> List[Dict[str, Any]]:
        """
        Retrieve all confirmed incident records.

        Returns:
            List of incident dictionaries.
        """
        with self._connect() as db:
            return [json.loads(row["payload"]) for row in db.execute("SELECT payload FROM phase_incidents")]

    def save_alert(self, alert: Dict[str, Any]) -> None:
        """
        Persist an administrative security alert.

        Args:
            alert: Alert payload dictionary.
        """
        with self._connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO alerts
                (alert_id, incident_id, node_id, owner_id, message, sent_at, acknowledged_at, escalated, channel, attack_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert["alert_id"], alert["incident_id"], alert["node_id"], alert["owner_id"],
                    alert["message"], alert["sent_at"], alert.get("acknowledged_at"),
                    int(alert.get("escalated", False)), alert.get("channel", "websocket"), alert.get("attack_type"),
                ),
            )
            db.commit()

    def list_alerts(self) -> List[Dict[str, Any]]:
        """
        Retrieve list of all administrative alerts sorted by timestamp descending.

        Returns:
            List of alert records.
        """
        with self._connect() as db:
            rows = db.execute("SELECT * FROM alerts ORDER BY sent_at DESC").fetchall()
        return [
            {
                "alert_id": row["alert_id"],
                "incident_id": row["incident_id"],
                "node_id": row["node_id"],
                "owner_id": row["owner_id"],
                "message": row["message"],
                "sent_at": row["sent_at"],
                "acknowledged_at": row["acknowledged_at"],
                "escalated": bool(row["escalated"]),
                "channel": row["channel"],
                "attack_type": row["attack_type"],
            }
            for row in rows
        ]

    def acknowledge_alert(self, alert_id: str, acknowledged_at: str) -> Optional[Dict[str, Any]]:
        """
        Mark an alert as acknowledged by administrator.

        Args:
            alert_id: Alert identifier.
            acknowledged_at: ISO 8601 UTC acknowledgement timestamp.

        Returns:
            Updated alert dictionary if found; None otherwise.
        """
        with self._connect() as db:
            db.execute("UPDATE alerts SET acknowledged_at = ? WHERE alert_id = ?", (acknowledged_at, alert_id))
            db.commit()
        return next((alert for alert in self.list_alerts() if alert["alert_id"] == alert_id), None)

    def escalate_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Mark an unacknowledged alert as escalated to team lead.

        Args:
            alert_id: Alert identifier.

        Returns:
            Updated alert dictionary if found; None otherwise.
        """
        with self._connect() as db:
            db.execute("UPDATE alerts SET escalated = 1 WHERE alert_id = ?", (alert_id,))
            db.commit()
        return next((alert for alert in self.list_alerts() if alert["alert_id"] == alert_id), None)
