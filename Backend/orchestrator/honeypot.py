"""
Dendritic-Cell Honeypot Decoy Engine for IMMUNE-NET.
A passive 'node-decoy' node attracts and captures attack traffic. Every captured
attack is logged to SQLite (honeypot_events) and its richer biomarker payload is
fed directly into the AntibodySynthesizer before any human alert is raised.
"""

from typing import Any, Dict, Optional
import logging

from common.nodes import HONEYPOT_NODE_ID, HONEYPOT_PROFILES
from common.schemas import ConfirmedThreat, Antibody, generate_uuid, utc_iso_now
from orchestrator.synthesizer import AntibodySynthesizer

logger = logging.getLogger("orchestrator.honeypot")

SCENARIO_ALIASES: Dict[str, str] = {
    "crypto_ransomware": "cryptominer",
    "cryptominer": "cryptominer",
    "syn_cytokine_flood": "port_scan",
    "port_scan": "port_scan",
    "exfil_parasite": "c2_beacon",
    "c2_beacon": "c2_beacon",
    "kernel_blight": "worm",
    "worm_ravage": "worm",
    "worm": "worm",
}


class HoneypotManager:
    """Captures decoy hits, synthesizes antibodies from captured biomarkers, and persists the audit trail."""

    def __init__(self, database: Any, synthesizer: Optional[AntibodySynthesizer] = None):
        self.db = database
        self.synthesizer = synthesizer or AntibodySynthesizer()
        self.event_counter: int = 0

    def capture_attack(
        self,
        source_ip: str,
        attack_vector: str,
        raw_payload: Optional[Dict[str, Any]] = None,
        auto_synthesize: bool = True,
    ) -> Dict[str, Any]:
        """
        Register an attack that touched the decoy node.

        Steps:
          1. Persist full telemetry payload to honeypot_events.
          2. Synthesize + sign a digital antibody from the captured biomarker signal.
          3. Persist the antibody into DB (antibody spread handled by orchestrator layer).

        Args:
            source_ip: Originating attacker IP.
            attack_vector: Attack classification (scenario name).
            raw_payload: Full captured payload of the decoy attack.
            auto_synthesize: Whether to immediately derive an antibody.

        Returns:
            Captured event record dict.
        """
        raw_payload = raw_payload or {}
        scenario = SCENARIO_ALIASES.get(
            str(attack_vector).lower()
            if isinstance(attack_vector, str)
            else attack_vector,
            attack_vector,
        )
        antibody_id = None

        if auto_synthesize:
            antibody = self._synthesize_antibody(scenario, source_ip, raw_payload)
            if antibody is not None:
                antibody_id = antibody.antibody_id
                self.db.save_antibody(antibody)
                logger.info(
                    f"[HONEYPOT] Antibody {antibody.antibody_id} synthesized from decoy capture "
                    f"'{scenario}' ({source_ip}) — no human alert required."
                )

        timestamp = utc_iso_now()
        self.event_counter += 1
        event_id = generate_uuid("hp-")
        self.db.save_honeypot_event(
            source_ip=source_ip,
            attack_vector=scenario,
            raw_payload=raw_payload,
            antibody_id=antibody_id,
            event_id=event_id,
            timestamp=timestamp,
        )
        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "attack_vector": scenario,
            "raw_payload": raw_payload,
            "antibody_id": antibody_id,
            "status": "captured",
            "node_id": HONEYPOT_NODE_ID,
        }

    def _synthesize_antibody(
        self,
        scenario: str,
        source_ip: str,
        raw_payload: Dict[str, Any],
    ) -> Optional[Antibody]:
        """
        Build a synthetic confirmed-threat from captured decoy payload and synthesize an antibody.
        Returns the synthesized Antibody or None on failure.
        """
        try:
            cpu = raw_payload.get("cpu_percent", 94.0)
            entropy = raw_payload.get("entropy", 0.92)
            connection_rate = raw_payload.get("connection_rate", 20.0)
            network_connections = raw_payload.get("network_connections", 60)
            process = raw_payload.get("process") or f"decoy_{scenario}_probe"
            destination = raw_payload.get("destination") or HONEYPOT_PROFILES.get(scenario, {}).get("service", "unknown")

            threat = ConfirmedThreat(
                threat_id=generate_uuid("threat-hp-"),
                classification=f"Decoy-Captured {scenario} Probe",
                affected_agent=HONEYPOT_NODE_ID,
                peer_agents=[],
                confidence_score=0.99,
                confidence_threshold=0.85,
                evidence_event_ids=[],
                detection_model_or_rule_version="dendritic-cell-decoy-v1",
                confirmed_at=utc_iso_now(),
                recommended_neutralization_action="quarantine_source",
                correlation_id=generate_uuid("corr-hp-"),
                scenario_type=scenario,
                narrative=(
                    f"Passive decoy {HONEYPOT_NODE_ID} captured a '{scenario}' probe from {source_ip}. "
                    f"Full biomarker payload captured and fed straight into antibody synthesis."
                ),
                biomarkers={
                    "cpu": cpu,
                    "entropy": entropy,
                    "connection_rate": connection_rate,
                    "network_connections": network_connections,
                    "process": process,
                    "source_ip": source_ip,
                },
            )
            return self.synthesizer.synthesize(threat)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(f"[HONEYPOT] Antibody synthesis failed for decoy capture: {exc}")
            return None

    def list_events(self, limit: int = 50) -> list:
        """Return captured honeypot events from SQLite."""
        return self.db.get_honeypot_events(limit=limit)