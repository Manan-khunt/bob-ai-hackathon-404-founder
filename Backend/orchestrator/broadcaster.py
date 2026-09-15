"""
WebSocket Broadcasting and Distribution Hub for IMMUNE-NET.
Dispatches antibodies, quarantine commands, and real-time immune events to agents and frontend clients.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Set, Any, Optional, List
from fastapi import WebSocket
from common.schemas import Antibody, QuarantineCommand, AgentAcknowledgement

logger = logging.getLogger("orchestrator.broadcaster")


class SwarmBroadcaster:
    """Central WebSocket broadcaster managing real-time distribution across agent swarm and UI dashboards."""

    def __init__(self, database: Any):
        self.db = database
        # Connected agent websockets: agent_id -> WebSocket
        self.agent_sockets: Dict[str, WebSocket] = {}
        # Connected frontend websockets
        self.frontend_sockets: Set[WebSocket] = set()
        # Delivery tracking: antibody_id -> { agent_id -> ack_status }
        self.delivery_status: Dict[str, Dict[str, str]] = {}

    async def register_agent(self, agent_id: str, websocket: WebSocket) -> None:
        """
        Register agent websocket connection and replay active unacknowledged antibodies.

        Args:
            agent_id: Connecting agent identifier.
            websocket: Established WebSocket connection.
        """
        self.agent_sockets[agent_id] = websocket
        logger.info(f"[AGENT CONNECTED] Agent {agent_id} connected to WebSocket hub.")

        # Replay all active antibodies to reconnecting/new agent
        active_abs = self.db.get_all_antibodies(status="active")
        for ab in active_abs:
            try:
                msg = {
                    "type": "DISTRIBUTE_ANTIBODY",
                    "antibody": ab.model_dump(mode="json"),
                }
                await websocket.send_text(json.dumps(msg))
            except Exception as e:
                logger.warning(f"Error sending active antibody {ab.antibody_id} to {agent_id}: {e}")

    def unregister_agent(self, agent_id: str) -> None:
        """
        Remove agent socket upon disconnect.

        Args:
            agent_id: Disconnecting agent identifier.
        """
        if agent_id in self.agent_sockets:
            del self.agent_sockets[agent_id]
            logger.info(f"[AGENT DISCONNECTED] Agent {agent_id} disconnected from WebSocket hub.")

    async def register_frontend(self, websocket: WebSocket) -> None:
        """
        Register frontend dashboard client and send initial sync of active antibodies.

        Args:
            websocket: Established WebSocket connection.
        """
        self.frontend_sockets.add(websocket)
        logger.info("[FRONTEND CONNECTED] Frontend dashboard connected to WebSocket hub.")

        # Replay active antibodies to frontend
        active_abs = self.db.get_all_antibodies(status="active")
        for ab in active_abs:
            try:
                await websocket.send_text(json.dumps({
                    "type": "NEW_ANTIBODY",
                    "antibody": ab.to_frontend_dict(),
                }))
            except Exception:
                pass

    def unregister_frontend(self, websocket: WebSocket) -> None:
        """
        Remove frontend socket upon disconnect.

        Args:
            websocket: Frontend WebSocket instance.
        """
        if websocket in self.frontend_sockets:
            self.frontend_sockets.remove(websocket)
            logger.info("[FRONTEND DISCONNECTED] Frontend dashboard disconnected from WebSocket hub.")

    # ---------------------------------------------------------
    # Broadcast Methods
    # ---------------------------------------------------------
    async def broadcast_antibody(self, antibody: Antibody) -> Dict[str, str]:
        """
        Broadcast newly synthesized antibody to:
        1. All connected agents via 'DISTRIBUTE_ANTIBODY'
        2. All frontend dashboards via 'NEW_ANTIBODY' & 'IMMUNE_EVENT'

        Args:
            antibody: Digital Antibody instance.

        Returns:
            Delivery status dictionary per connected agent.
        """
        ab_id = antibody.antibody_id
        self.delivery_status[ab_id] = {}

        # 1. Send to all agents
        agent_msg = json.dumps({
            "type": "DISTRIBUTE_ANTIBODY",
            "antibody": antibody.model_dump(mode="json"),
        })

        for agent_id, ws in list(self.agent_sockets.items()):
            try:
                await ws.send_text(agent_msg)
                self.delivery_status[ab_id][agent_id] = "sent"
            except Exception as e:
                logger.error(f"Failed to send antibody {ab_id} to agent {agent_id}: {e}")
                self.delivery_status[ab_id][agent_id] = "failed"

        logger.info(f"[ANTIBODY BROADCAST] Broadcast antibody {ab_id} to {len(self.delivery_status[ab_id])} agents.")

        # 2. Send to frontend dashboards
        frontend_msg = json.dumps({
            "type": "NEW_ANTIBODY",
            "antibody": antibody.to_frontend_dict(),
        })
        await self._send_frontend_raw(frontend_msg)

        # Send an IMMUNE_EVENT to timeline
        await self.send_frontend_event({
            "type": "ANTIBODY_SYNTHESIS",
            "severity": "SUCCESS",
            "title": f"Digital Antibody Synthesized: {antibody.antibody_id}",
            "detail": f"Autonomous synthesis completed. Universal neutralization rule: {antibody.ebpf_rule}",
            "nodeId": "ALL",
            "nodeName": "Swarm Orchestrator",
            "metadata": {
                "signature": antibody.antibody_id,
                "rule": antibody.detection_rule,
                "threatType": antibody.threat_type,
                "mitre": antibody.mitre,
            },
        })

        return self.delivery_status[ab_id]

    async def send_quarantine_command(self, command: QuarantineCommand) -> None:
        """
        Send authenticated quarantine command to the specific target agent.

        Args:
            command: Signed QuarantineCommand instance.
        """
        target_id = command.agent_id
        cmd_msg = json.dumps({
            "type": "QUARANTINE_COMMAND",
            "command": command.model_dump(),
        })

        if target_id in self.agent_sockets:
            try:
                await self.agent_sockets[target_id].send_text(cmd_msg)
                logger.warning(f"[QUARANTINE DISPATCHED] Quarantine command {command.command_id} delivered to {target_id}")
            except Exception as e:
                logger.error(f"Failed to deliver quarantine command to {target_id}: {e}")

        # Notify frontend
        await self.send_frontend_patch(target_id, {
            "status": "quarantined",
            "biomarkers": {"socketLoad": 0, "entropy": 0.95},
        })

        await self.send_frontend_event({
            "type": "INFLAMMATORY_QUARANTINE",
            "severity": "ALERT",
            "title": f"Inflammation Barrier: {target_id} Quarantined",
            "detail": f"Autonomous quarantine enacted. Reason: {command.reason}",
            "nodeId": target_id,
            "nodeName": target_id,
            "metadata": {"commandId": command.command_id, "threatId": command.threat_id},
        })

    async def send_frontend_patch(self, node_id: str, patch: Dict[str, Any]) -> None:
        """
        Send NODE_UPDATE patch to frontend dashboards.

        Args:
            node_id: Target node identifier.
            patch: State dictionary updates.
        """
        msg = json.dumps({
            "type": "NODE_UPDATE",
            "nodeId": node_id,
            "patch": patch,
        })
        await self._send_frontend_raw(msg)

    async def send_frontend_event(self, event_data: Dict[str, Any]) -> None:
        """
        Send structured IMMUNE_EVENT to frontend timeline.

        Args:
            event_data: Event properties and metadata dictionary.
        """
        from common.schemas import generate_uuid
        import time
        payload = {
            "type": "IMMUNE_EVENT",
            "event": {
                "id": generate_uuid("evt-"),
                "timestamp": datetime_to_time_str(),
                "timeMs": int(time.time() * 1000),
                **event_data,
            },
        }
        await self._send_frontend_raw(json.dumps(payload))

    async def _send_frontend_raw(self, msg: str) -> None:
        dead_sockets = set()
        for ws in self.frontend_sockets:
            try:
                await ws.send_text(msg)
            except Exception:
                dead_sockets.add(ws)
        for dead in dead_sockets:
            self.frontend_sockets.remove(dead)

    def record_agent_ack(self, ack: AgentAcknowledgement) -> None:
        """
        Record agent receipt/activation acknowledgment.

        Args:
            ack: AgentAcknowledgement instance.
        """
        self.db.save_acknowledgement(ack)
        if ack.target_id not in self.delivery_status:
            self.delivery_status[ack.target_id] = {}
        self.delivery_status[ack.target_id][ack.agent_id] = ack.status
        logger.info(f"[AGENT ACK] Agent {ack.agent_id} reported '{ack.status}' for target {ack.target_id}")

    def get_distribution_status(self, antibody_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Return delivery and activation stats across the swarm.

        Args:
            antibody_id: Optional antibody ID to filter by.

        Returns:
            Delivery status dictionary.
        """
        if antibody_id:
            return self.delivery_status.get(antibody_id, {})
        return self.delivery_status


def datetime_to_time_str() -> str:
    """Format current time as human readable string."""
    return datetime.now().strftime("%I:%M:%S %p")
