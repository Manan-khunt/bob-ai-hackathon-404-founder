"""
Reversible Autonomous Quarantine and Escalation Engine for IMMUNE-NET.
Manages node isolation states, consecutive anomaly confidence thresholds,
and time-based administrative alert notifications and escalations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
import asyncio
import uuid
import logging
from typing import Awaitable, Callable, Dict, Any, List, Optional

import httpx

logger = logging.getLogger("orchestrator.quarantine")


@dataclass
class QuarantineRecord:
    """Tracking record for an agent's containment and fence status."""

    agent_id: str
    state: str = "pending"
    reason: str = ""
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    consecutive_high_confidence: int = 0


class QuarantineManager:
    """Thread-safe quarantine controller monitoring sustained confidence levels to fence or release agents."""

    def __init__(self, sustained_frames: int = 3, threshold: float = 0.95):
        self.sustained_frames = sustained_frames
        self.threshold = threshold
        self.records: Dict[str, QuarantineRecord] = {}
        self._lock = Lock()

    def observe(self, agent_id: str, confidence: float, reason: str = "") -> QuarantineRecord:
        """
        Observe a new confidence evaluation frame and fence node if sustained threshold is crossed.

        Args:
            agent_id: Target agent identifier.
            confidence: Normalized threat confidence (0.0 - 1.0).
            reason: Human-readable rationale.

        Returns:
            Updated QuarantineRecord.
        """
        with self._lock:
            record = self.records.setdefault(agent_id, QuarantineRecord(agent_id=agent_id))
            if record.state == "fenced":
                return record
            record.consecutive_high_confidence = (
                record.consecutive_high_confidence + 1 if confidence >= self.threshold else 0
            )
            if record.consecutive_high_confidence >= self.sustained_frames:
                record.state = "fenced"
                record.reason = reason
                record.updated_at = datetime.now(timezone.utc).isoformat()
                logger.warning(f"[QUARANTINE ACTIVATED] Node {agent_id} fenced after {self.sustained_frames} sustained frames (Reason: {reason})")
            return record

    def fence(self, agent_id: str, reason: str = "manual fence") -> QuarantineRecord:
        """
        Force immediate isolation/containment of a node.

        Args:
            agent_id: Target agent identifier.
            reason: Justification string.

        Returns:
            Updated QuarantineRecord.
        """
        with self._lock:
            record = self.records.setdefault(agent_id, QuarantineRecord(agent_id=agent_id))
            record.state = "fenced"
            record.reason = reason
            record.updated_at = datetime.now(timezone.utc).isoformat()
            logger.warning(f"[MANUAL FENCE] Node {agent_id} isolated (Reason: {reason})")
            return record

    def unfence(self, agent_id: str, reason: str = "manual unfence") -> QuarantineRecord:
        """
        Release a node from quarantine back into active swarm mesh.

        Args:
            agent_id: Target agent identifier.
            reason: Justification string.

        Returns:
            Updated QuarantineRecord.
        """
        with self._lock:
            record = self.records.setdefault(agent_id, QuarantineRecord(agent_id=agent_id))
            record.state = "unfenced"
            record.reason = reason
            record.consecutive_high_confidence = 0
            record.updated_at = datetime.now(timezone.utc).isoformat()
            logger.info(f"[UNFENCED] Node {agent_id} returned to normal swarm state (Reason: {reason})")
            return record

    def is_fenced(self, agent_id: str) -> bool:
        """Check if node is currently in fenced/quarantined state."""
        return self.records.get(agent_id, QuarantineRecord(agent_id)).state == "fenced"

    def snapshot(self) -> List[Dict[str, Any]]:
        """Return list copy of all quarantine records."""
        return [record.__dict__.copy() for record in self.records.values()]


_escalation_tasks: Dict[str, asyncio.Task] = {}


async def notify_admins(
    incident: Dict[str, Any],
    owner_id: str,
    memory: Any,
    send_alert: Callable[[Dict[str, Any]], Awaitable[None]],
    webhook_url: Optional[str] = None,
    escalation_seconds: float = 45.0,
) -> Dict[str, Any]:
    """
    Notify designated node owner first, then schedule automatic escalation if unacknowledged.

    Args:
        incident: Incident payload dictionary.
        owner_id: Assigned owner identifier (e.g. 'admin_1').
        memory: Persistence memory store.
        send_alert: Async callable to dispatch alert to HUD/WebSocket listeners.
        webhook_url: Optional external webhook target.
        escalation_seconds: Duration before escalating to team lead.

    Returns:
        Created alert record dictionary.
    """
    alert_id = f"alert-{uuid.uuid4()}"
    sent_at = datetime.now(timezone.utc).isoformat()
    attack_name = incident.get("attack_type", incident.get("scenario", "unknown"))
    node_id = incident["node_id"]
    confidence_val = incident.get("confidence", 0)

    message = f"{attack_name} confirmed on {node_id} with confidence {confidence_val:.2f}."
    alert = {
        "alert_id": alert_id,
        "incident_id": incident["incident_id"],
        "node_id": node_id,
        "owner_id": owner_id,
        "message": message,
        "sent_at": sent_at,
        "acknowledged_at": None,
        "escalated": False,
        "channel": "websocket",
        "attack_type": attack_name,
    }
    memory.save_alert(alert)
    logger.info(f"[ALERT DISPATCHED] Alert {alert_id} sent to owner {owner_id} for {attack_name} on {node_id}")

    await send_alert({
        "event": "admin_alert",
        "alert_id": alert_id,
        "node_id": node_id,
        "owner_id": owner_id,
        "attack_type": attack_name,
        "confidence": confidence_val,
        "message": message,
        "ts": sent_at,
        "status": "sent",
    })

    if webhook_url:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(webhook_url, json={"text": message, "alert": alert})
        except Exception as e:
            logger.warning(f"Webhook notification failed for {alert_id}: {e}")

    async def escalate_later():
        await asyncio.sleep(escalation_seconds)
        current = next((item for item in memory.list_alerts() if item["alert_id"] == alert_id), None)
        if not current or current["acknowledged_at"]:
            return
        current = memory.escalate_alert(alert_id) or current
        logger.warning(f"[ALERT ESCALATED] Unacknowledged alert {alert_id} escalated to team_lead for node {node_id}")
        await send_alert({
            "event": "admin_alert",
            "alert_id": alert_id,
            "node_id": current["node_id"],
            "owner_id": "team_lead",
            "attack_type": attack_name,
            "confidence": confidence_val,
            "message": f"ESCALATION: {message}",
            "ts": datetime.now(timezone.utc).isoformat(),
            "status": "escalated",
        })

    _escalation_tasks[alert_id] = asyncio.create_task(escalate_later())
    return alert


def cancel_escalation(alert_id: str) -> None:
    """
    Cancel pending escalation task when an alert is acknowledged.

    Args:
        alert_id: Target alert identifier.
    """
    task = _escalation_tasks.pop(alert_id, None)
    if task and not task.done():
        task.cancel()
        logger.info(f"[ESCALATION CANCELLED] Alert {alert_id} escalation cancelled upon acknowledgement.")
