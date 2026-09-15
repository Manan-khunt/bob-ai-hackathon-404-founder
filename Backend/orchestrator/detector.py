"""
Adaptive Immunity Threat Detection and Correlation Engine for IMMUNE-NET.
Correlates agent-local anomaly signals with aggregated telemetry to confirm high-confidence threats,
mapping detections to MITRE ATT&CK techniques and generating executive BLUF incident summaries.
"""

from typing import List, Dict, Any, Optional
import collections
import logging
from common.schemas import (
    TelemetryEvent,
    LocalAnomalyEvent,
    ConfirmedThreat,
    generate_uuid,
    utc_iso_now,
)
from common.nodes import NODES_CATALOG
from orchestrator.mitre_mapping import get_mitre_technique
from orchestrator.bluf import generate_bluf_summary
from orchestrator.explain import generate_explanation

logger = logging.getLogger("orchestrator.detector")


class AdaptiveCorrelator:
    """Multi-node adaptive correlation engine confirming threats from innate anomaly signals."""

    def __init__(self, window_seconds: float = 10.0, confidence_threshold: float = 0.85):
        self.window_seconds = window_seconds
        self.confidence_threshold = confidence_threshold
        # Sliding buffer of recent anomalies by agent
        self.anomaly_buffer: Dict[str, List[LocalAnomalyEvent]] = collections.defaultdict(list)
        # Sliding buffer of recent telemetry by agent
        self.telemetry_buffer: Dict[str, List[TelemetryEvent]] = collections.defaultdict(list)

    def ingest_telemetry(self, telemetry: TelemetryEvent) -> None:
        """
        Buffer incoming telemetry and prune old records beyond window limit.

        Args:
            telemetry: TelemetryEvent received from an agent.
        """
        self.telemetry_buffer[telemetry.agent_id].append(telemetry)
        if len(self.telemetry_buffer[telemetry.agent_id]) > 50:
            self.telemetry_buffer[telemetry.agent_id] = self.telemetry_buffer[telemetry.agent_id][-50:]

    def ingest_anomaly(self, anomaly: LocalAnomalyEvent) -> Optional[ConfirmedThreat]:
        """
        Process local anomaly event, correlate against evidence, and confirm threat if policy is met.

        Args:
            anomaly: LocalAnomalyEvent from endpoint agent's innate detector.

        Returns:
            ConfirmedThreat if correlation policy succeeds; None otherwise.
        """
        agent_id = anomaly.agent_id
        self.anomaly_buffer[agent_id].append(anomaly)
        if len(self.anomaly_buffer[agent_id]) > 20:
            self.anomaly_buffer[agent_id] = self.anomaly_buffer[agent_id][-20:]

        recent_telem = self.telemetry_buffer.get(agent_id, [])
        return self._evaluate_correlation_policy(anomaly, recent_telem)

    def _evaluate_correlation_policy(
        self,
        anomaly: LocalAnomalyEvent,
        recent_telem: List[TelemetryEvent],
    ) -> Optional[ConfirmedThreat]:
        """
        Evaluates explicit confidence policies for Cryptominer, Port Scan, C2 Beacon, and Worm.

        Args:
            anomaly: The triggering anomaly event.
            recent_telem: Historical telemetry frames from the same agent.

        Returns:
            ConfirmedThreat if correlation criteria met; None if under threshold.
        """
        evidence_ids = [anomaly.event_id]
        if recent_telem:
            evidence_ids.extend([t.event_id for t in recent_telem[-5:]])

        # Extract features from anomaly evidence window and recent telemetry
        evidence = anomaly.evidence_window or {}
        latest_telem = recent_telem[-1] if recent_telem else None

        cpu = evidence.get("cpu_percent", latest_telem.cpu_percent if latest_telem else 0.0)
        conn_rate = evidence.get("connection_rate", latest_telem.connection_rate if latest_telem else 0.0)
        connections = evidence.get("network_connections", latest_telem.network_connections if latest_telem else 0)
        process = (evidence.get("process") or (latest_telem.process if latest_telem else "")).lower()
        destination = (evidence.get("destination") or (latest_telem.destination if latest_telem else "")).lower()
        entropy = evidence.get("entropy", latest_telem.entropy if latest_telem else 0.1)
        scenario_hint = anomaly.scenario_hint or (latest_telem.scenario_id if latest_telem else None)

        confirmed_threat: Optional[ConfirmedThreat] = None

        # 1. Cryptomining Confirmation Policy
        if scenario_hint in ("cryptominer", "crypto_ransomware") or (not scenario_hint and (
            ("crypto" in process or "miner" in process or "xmrig" in process)
            or (cpu >= 70.0 and entropy > 0.6)
        )):
            confidence = 0.98 if cpu >= 75.0 else 0.91
            mitre = get_mitre_technique("cryptominer")
            confirmed_threat = ConfirmedThreat(
                threat_id=generate_uuid("threat-crypto-"),
                classification="Autonomous Cryptominer / Ransomware Process",
                affected_agent=anomaly.agent_id,
                peer_agents=NODES_CATALOG.get(anomaly.agent_id, {}).get("peers", []),
                confidence_score=confidence,
                confidence_threshold=self.confidence_threshold,
                evidence_event_ids=evidence_ids,
                detection_model_or_rule_version="adaptive-correlator-crypto-v1",
                confirmed_at=utc_iso_now(),
                recommended_neutralization_action="quarantine_source",
                correlation_id=anomaly.correlation_id,
                scenario_type="cryptominer",
                narrative=(
                    f"Sustained elevated CPU utilization ({cpu:.1f}%) and abnormal process entropy ({entropy:.2f}) "
                    f"correlated with unauthorized execution '{process}' on {anomaly.agent_id}."
                ),
                biomarkers={
                    "cpu": cpu,
                    "entropy": entropy,
                    "process": process,
                    "anomalyScore": anomaly.score,
                },
                mitre=mitre,
            )

        # 2. Port Scan / Fan-out Confirmation Policy
        elif scenario_hint in ("port_scan", "syn_cytokine_flood") or (not scenario_hint and (
            ("scan" in process or "nmap" in process or "syn" in process)
            or (conn_rate >= 15.0 or connections >= 80)
        )):
            confidence = 0.97 if conn_rate >= 18.0 else 0.89
            mitre = get_mitre_technique("port_scan")
            confirmed_threat = ConfirmedThreat(
                threat_id=generate_uuid("threat-scan-"),
                classification="Rapid TCP/SYN Port Scanner & Fan-Out Probe",
                affected_agent=anomaly.agent_id,
                peer_agents=NODES_CATALOG.get(anomaly.agent_id, {}).get("peers", []),
                confidence_score=confidence,
                confidence_threshold=self.confidence_threshold,
                evidence_event_ids=evidence_ids,
                detection_model_or_rule_version="adaptive-correlator-scan-v1",
                confirmed_at=utc_iso_now(),
                recommended_neutralization_action="quarantine_source",
                correlation_id=anomaly.correlation_id,
                scenario_type="port_scan",
                narrative=(
                    f"Connection fan-out rate spike ({conn_rate:.1f}/s) and multi-port sweep detected from "
                    f"originating node {anomaly.agent_id}."
                ),
                biomarkers={
                    "connection_rate": conn_rate,
                    "socketLoad": connections,
                    "process": process,
                    "anomalyScore": anomaly.score,
                },
                mitre=mitre,
            )

        # 3. C2 Beaconing / Stealth Exfiltration Policy
        elif scenario_hint in ("c2_beacon", "exfil_parasite") or (not scenario_hint and (
            ("beacon" in process or "exfil" in process or "evil" in destination or (":53" in destination and entropy > 0.5))
            or (destination and any(x in destination for x in ["c2", "exfil", "parasite", "tunnel"]))
        )):
            confidence = 0.95
            mitre = get_mitre_technique("c2_beacon")
            confirmed_threat = ConfirmedThreat(
                threat_id=generate_uuid("threat-c2-"),
                classification="Command-and-Control (C2) Heartbeat & Exfiltration Tunnel",
                affected_agent=anomaly.agent_id,
                peer_agents=NODES_CATALOG.get(anomaly.agent_id, {}).get("peers", []),
                confidence_score=confidence,
                confidence_threshold=self.confidence_threshold,
                evidence_event_ids=evidence_ids,
                detection_model_or_rule_version="adaptive-correlator-c2-v1",
                confirmed_at=utc_iso_now(),
                recommended_neutralization_action="quarantine_source",
                correlation_id=anomaly.correlation_id,
                scenario_type="c2_beacon",
                narrative=(
                    f"Periodic outbound heartbeats to suspicious endpoint '{destination}' with high payload entropy "
                    f"detected on {anomaly.agent_id}."
                ),
                biomarkers={
                    "destination": destination,
                    "entropy": entropy,
                    "process": process,
                    "anomalyScore": anomaly.score,
                },
                mitre=mitre,
            )

        # 4. Worm Lateral Spread Policy
        elif scenario_hint in ("worm", "worm_ravage", "kernel_blight") or (not scenario_hint and (
            ("worm" in process or "blight" in process or "spread" in process)
            or (any(p in destination for p in ["10.0.1.", "node-"]) and connections >= 3)
        )):
            confidence = 0.99
            mitre = get_mitre_technique("worm")
            confirmed_threat = ConfirmedThreat(
                threat_id=generate_uuid("threat-worm-"),
                classification="Self-Replicating Kernel Worm & Lateral Propagation",
                affected_agent=anomaly.agent_id,
                peer_agents=NODES_CATALOG.get(anomaly.agent_id, {}).get("peers", []),
                confidence_score=confidence,
                confidence_threshold=self.confidence_threshold,
                evidence_event_ids=evidence_ids,
                detection_model_or_rule_version="adaptive-correlator-worm-v1",
                confirmed_at=utc_iso_now(),
                recommended_neutralization_action="quarantine_source",
                correlation_id=anomaly.correlation_id,
                scenario_type="worm",
                narrative=(
                    f"Rapid lateral propagation bursts attempting peer cluster traversal from "
                    f"compromised agent {anomaly.agent_id}."
                ),
                biomarkers={
                    "lateralSpread": True,
                    "connections": connections,
                    "process": process,
                    "anomalyScore": anomaly.score,
                },
                mitre=mitre,
            )

        # Fallback Generic Anomaly Confirmation if score is very extreme
        elif anomaly.score >= 90.0:
            confidence = 0.88
            mitre = get_mitre_technique("unknown")
            confirmed_threat = ConfirmedThreat(
                threat_id=generate_uuid("threat-generic-"),
                classification="High-Entropy Unclassified Behavioral Anomaly",
                affected_agent=anomaly.agent_id,
                peer_agents=NODES_CATALOG.get(anomaly.agent_id, {}).get("peers", []),
                confidence_score=confidence,
                confidence_threshold=self.confidence_threshold,
                evidence_event_ids=evidence_ids,
                detection_model_or_rule_version="adaptive-correlator-generic-v1",
                confirmed_at=utc_iso_now(),
                recommended_neutralization_action="quarantine_source",
                correlation_id=anomaly.correlation_id,
                scenario_type="generic_anomaly",
                narrative=f"Multi-metric behavioral drift exceeding 90th percentile on {anomaly.agent_id}.",
                biomarkers={"anomalyScore": anomaly.score},
                mitre=mitre,
            )

        if confirmed_threat:
            owner_id = NODES_CATALOG.get(anomaly.agent_id, {}).get("owner_id", "admin_1")

            # Generate explainability data for the threat
            explanation_data = generate_explanation(
                evidence=evidence,
                scenario_hint=confirmed_threat.scenario_type,
                anomaly_score=anomaly.score,
            )
            confirmed_threat.explanation = explanation_data

            incident_dict = {
                "node_id": confirmed_threat.affected_agent,
                "attack_type": confirmed_threat.scenario_type,
                "status": "confirmed",
                "confidence": confirmed_threat.confidence_score,
                "detected_at": confirmed_threat.confirmed_at,
                "owner_id": owner_id,
                "mitre": confirmed_threat.mitre,
                "cpu_usage": evidence.get("cpu_percent"),
                "memory_usage": evidence.get("memory_percent"),
                "entropy": evidence.get("entropy"),
                "connections": evidence.get("network_connections"),
                "connection_rate": evidence.get("connection_rate"),
                "process": evidence.get("process"),
            }
            confirmed_threat.bluf_summary = generate_bluf_summary(
                incident_dict,
                explanation=explanation_data,
            )

        return confirmed_threat
