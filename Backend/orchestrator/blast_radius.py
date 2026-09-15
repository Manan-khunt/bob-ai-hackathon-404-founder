"""
Blast Radius Propagation Model for IMMUNE-NET.
Predicts lateral movement spread from an infected node across the swarm topology using:

    risk = shared_subnet_risk * connection_rate_factor * service_exposure_score

Any at-risk neighbor with an estimated fall time under 15 seconds is pre-emptively
quarantined to contain the outbreak before it can spread.
"""

from typing import Dict, Any, List, Optional
import logging

from common.nodes import NODES_CATALOG, HONEYPOT_NODE_ID

logger = logging.getLogger("orchestrator.blast_radius")

# Service exposure score per topology node. Higher = more attractive lateral-movement target.
SERVICE_EXPOSURE: Dict[str, float] = {
    "node-alpha": 1.6,
    "node-beta": 1.8,
    "node-gamma": 2.8,
    "node-delta": 1.9,
    "node-epsilon": 1.4,
    "node-zeta": 1.3,
    "node-eta": 1.5,
    "node-theta": 2.0,
    HONEYPOT_NODE_ID: 5.0,
}

# Estimated seconds to fall: seconds = FALL_TIME_CONSTANT / risk
FALL_TIME_CONSTANT: float = 32.0
PREEMPTIVE_QUARANTINE_WINDOW_SECONDS: float = 15.0

# Periodic combined-scenario baselines to fall back on when telemetry is sparse.
DEFAULT_TELEMETRY: Dict[str, Any] = {
    "connection_rate": 8.0,
    "cpu_percent": 40.0,
    "network_connections": 12,
    "entropy": 0.4,
    "destination": "10.0.1.1:443",
}


def _shared_subnet_risk(infected_node: str, peer_id: str) -> float:
    """1.0 if peer shares the mesh subnet with the infected host, else 0.4."""
    infected_ip = NODES_CATALOG.get(infected_node, {}).get("ip", "10.0.1.50")
    peer_ip = NODES_CATALOG.get(peer_id, {}).get("ip", "10.0.1.50")
    infected_subnet = ".".join(infected_ip.split(".")[:3])
    peer_subnet = ".".join(peer_ip.split(".")[:3])
    return 1.0 if infected_subnet == peer_subnet else 0.4


def _connection_rate_factor(telemetry: Dict[str, Any]) -> float:
    """Escalate propagation speed with observed outbound connection velocity."""
    rate = telemetry.get("connection_rate")
    if rate is None:
        rate = DEFAULT_TELEMETRY["connection_rate"]
    try:
        rate = float(rate)
    except (TypeError, ValueError):
        rate = DEFAULT_TELEMETRY["connection_rate"]
    return min(2.5, max(0.5, rate / 8.0))


def _service_exposure_score(peer_id: str) -> float:
    return SERVICE_EXPOSURE.get(peer_id, 1.2)


def _risk_level(risk_score: float) -> str:
    if risk_score >= 2.4:
        return "critical"
    if risk_score >= 1.6:
        return "high"
    return "medium"


def predict_blast_radius(infected_node: str, telemetry: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Model lateral movement from an infected node to every direct peer.

    Auto-triggers pre-emptive quarantine for any peer with estimated seconds
    to fall below the 15 second safety window.

    Args:
        infected_node: ID of the compromised node.
        telemetry: Optional biomarker telemetry dict of the infected node.

    Returns:
        Ordered chain (highest risk first) of {
            node_id, risk_score, estimated_seconds_to_fall, risk_level, auto_quarantined
        }.
    """
    telemetry = telemetry or {}
    infected = NODES_CATALOG.get(infected_node, {})
    peers = infected.get("peers", [])

    if not peers:
        peers = [nid for nid in NODES_CATALOG if nid != infected_node]

    connection_factor = _connection_rate_factor(telemetry)

    chain: List[Dict[str, Any]] = []
    for peer_id in peers:
        risk = (
            _shared_subnet_risk(infected_node, peer_id)
            * connection_factor
            * _service_exposure_score(peer_id)
        )
        seconds = max(2, int(round(FALL_TIME_CONSTANT / max(risk, 1e-6))))
        entry = {
            "node_id": peer_id,
            "risk_score": round(risk, 3),
            "estimated_seconds_to_fall": seconds,
            "risk_level": _risk_level(risk),
            "auto_quarantined": False,
        }
        chain.append(entry)

    chain.sort(key=lambda e: e["risk_score"], reverse=True)

    # Auto-trigger pre-emptive quarantine for imminent-fall peers.
    from orchestrator.quarantine import QuarantineManager
    quarantine_manager = QuarantineManager()
    for entry in chain:
        if entry["estimated_seconds_to_fall"] < PREEMPTIVE_QUARANTINE_WINDOW_SECONDS:
            try:
                record = quarantine_manager.fence(
                    entry["node_id"],
                    reason=f"pre-emptive blast-radius containment from {infected_node}",
                )
                entry["auto_quarantined"] = True
                entry["command_id"] = record.updated_at
                entry["status"] = record.state
                logger.warning(
                    f"[BLAST RADIUS] Pre-emptive quarantine triggered for {entry['node_id']} "
                    f"(fall in {entry['estimated_seconds_to_fall']}s, risk={entry['risk_score']})"
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.error(f"[BLAST RADIUS] Pre-emptive quarantine failed for {entry['node_id']}: {exc}")

    return chain


def auto_quarantine_targets(chain: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return the subset of the chain that required pre-emptive quarantine."""
    return [entry for entry in chain if entry.get("auto_quarantined")]