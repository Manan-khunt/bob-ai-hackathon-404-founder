"""
IMMUNE-NET Endpoint Agent Daemon.
Runs innate anomaly detection, enforces autonomous quarantine, and executes sub-2ms antibody neutralization.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import asyncio
import json
import logging
from typing import Optional
import websockets
import uvicorn
from fastapi import FastAPI

from common.schemas import (
    TelemetryEvent,
    LocalAnomalyEvent,
    Antibody,
    QuarantineCommand,
    AgentAcknowledgement,
    utc_iso_now,
    generate_uuid
)
from agent.detector import InnateAnomalyDetector
from agent.immune_memory import AgentImmuneMemory
from agent.telemetry_generator import TelemetryGenerator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (%(name)s): %(message)s")

agent_health_app = FastAPI(title="IMMUNE-NET Agent")
_health_agent: Optional["ImmuneAgent"] = None


@agent_health_app.get("/health")
async def health():
    return {
        "status": "healthy" if _health_agent is None or _health_agent.status != "quarantined" else "quarantined",
        "agent_id": _health_agent.agent_id if _health_agent else None,
    }

class ImmuneAgent:
    def __init__(self, agent_id: str, orchestrator_url: str = "ws://localhost:8000/ws"):
        self.agent_id = agent_id
        self.orchestrator_url = f"{orchestrator_url}?agent_id={agent_id}"
        self.status = "healthy"  # healthy, suspected, quarantined, immune
        self.detector = InnateAnomalyDetector(agent_id=agent_id)
        self.memory = AgentImmuneMemory(agent_id=agent_id)
        self.telemetry_gen = TelemetryGenerator(agent_id=agent_id)
        self.ws: Optional[websockets.WebSocketClientProtocol] = None
        self.running = False
        self.logger = logging.getLogger(f"agent.{agent_id}")

    async def start(self):
        """Start agent lifecycle and background loops."""
        self.running = True
        self.logger.info(f"Starting IMMUNE-NET Agent '{self.agent_id}' (Status: {self.status})")

        while self.running:
            try:
                self.logger.info(f"Connecting to orchestrator at {self.orchestrator_url}...")
                async with websockets.connect(self.orchestrator_url) as ws:
                    self.ws = ws
                    self.logger.info(f"Connected to orchestrator. Initiating innate surveillance loop.")

                    # Start concurrent tasks: telemetry loop and websocket listener
                    telem_task = asyncio.create_task(self._telemetry_loop())
                    listener_task = asyncio.create_task(self._listener_loop())

                    done, pending = await asyncio.wait(
                        [telem_task, listener_task],
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    for task in pending:
                        task.cancel()

            except (websockets.exceptions.ConnectionClosed, ConnectionRefusedError, OSError) as e:
                self.logger.warning(f"Connection lost or unavailable ({e}). Reconnecting in 2 seconds...")
                await asyncio.sleep(2.0)
            except Exception as e:
                self.logger.error(f"Unexpected error in agent loop: {e}", exc_info=True)
                await asyncio.sleep(2.0)

    async def _telemetry_loop(self):
        """Periodically generate telemetry and perform fast local anomaly detection."""
        while self.running and self.ws:
            if self.status == "quarantined":
                await asyncio.sleep(1.0)
                continue
            telem = self.telemetry_gen.generate()

            # Innate Immunity: Fast local scoring
            score, anomaly_event = self.detector.evaluate(telem)

            if anomaly_event and self.status != "quarantined":
                self.logger.warning(f"LOCAL ANOMALY TRIGGERED on {self.agent_id} (Score: {score:.1f}). Emitting signal to orchestrator.")
                self.status = "suspected"
                msg = {
                    "type": "LOCAL_ANOMALY",
                    "anomaly": anomaly_event.model_dump()
                }
                await self.ws.send(json.dumps(msg))
            else:
                # Normal heartbeat telemetry
                msg = {
                    "type": "TELEMETRY",
                    "telemetry": telem.model_dump()
                }
                try:
                    await self.ws.send(json.dumps(msg))
                except Exception:
                    pass

            await asyncio.sleep(1.0)

    async def _listener_loop(self):
        """Listen for incoming commands, antibodies, or attack simulations from orchestrator."""
        while self.running and self.ws:
            try:
                raw_msg = await self.ws.recv()
            except (websockets.exceptions.ConnectionClosed, asyncio.CancelledError, OSError):
                break
            try:
                data = json.loads(raw_msg)
            except json.JSONDecodeError:
                continue

            msg_type = data.get("type")

            # 1. Received Signed Antibody Broadcast
            if msg_type == "DISTRIBUTE_ANTIBODY":
                ab_payload = data.get("antibody")
                if ab_payload:
                    antibody = Antibody(**ab_payload)
                    success, status_code = self.memory.install_antibody(antibody)

                    if success and status_code == "applied":
                        self.status = "immune"

                    # Send acknowledgement back to orchestrator
                    ack = AgentAcknowledgement(
                        agent_id=self.agent_id,
                        target_id=antibody.antibody_id,
                        type="antibody_receipt",
                        status=status_code,
                        details=f"Installed antibody version {antibody.version}"
                    )
                    await self.ws.send(json.dumps({
                        "type": "AGENT_ACK",
                        "ack": ack.model_dump()
                    }))

            # 2. Received Quarantine Command
            elif msg_type == "QUARANTINE_COMMAND":
                cmd_payload = data.get("command")
                if cmd_payload:
                    cmd = QuarantineCommand(**cmd_payload)
                    self.status = "quarantined"
                    self.telemetry_gen.clear_attack()
                    self.logger.info(f"ENFORCING QUARANTINE on {self.agent_id}. Severing lateral connectivity.")

                    ack = AgentAcknowledgement(
                        agent_id=self.agent_id,
                        target_id=cmd.command_id,
                        type="quarantine_applied",
                        status="applied",
                        details=f"Quarantined due to {cmd.reason}"
                    )
                    await self.ws.send(json.dumps({
                        "type": "AGENT_ACK",
                        "ack": ack.model_dump()
                    }))

            # 3. Simulate Attack (Used by Demo / Attacker)
            elif msg_type == "SIMULATE_ATTACK":
                scenario = data.get("scenario", "cryptominer")
                mode = data.get("mode", "first_attack")

                # Check if learned antibody already protects this node!
                blocked, ab, latency_ms = self.memory.match_and_neutralize(scenario)

                if blocked and ab:
                    self.logger.info(f"REPEAT ATTACK BLOCKED by memory antibody {ab.antibody_id} in {latency_ms}ms!")
                    self.status = "immune"
                    # Notify orchestrator of successful sub-2ms deflection
                    await self.ws.send(json.dumps({
                        "type": "ANTIBODY_NEUTRALIZATION",
                        "agent_id": self.agent_id,
                        "antibody_id": ab.antibody_id,
                        "scenario": scenario,
                        "latency_ms": latency_ms
                    }))
                else:
                    self.logger.warning(f"Injecting live attack '{scenario}' into {self.agent_id} (No active antibody yet)")
                    self.telemetry_gen.inject_attack(scenario, ticks=8)

            # 4. Reset Simulation
            elif msg_type == "RESET_BASELINE":
                self.status = "healthy"
                self.telemetry_gen.clear_attack()
                self.memory.antibodies.clear()
                self.logger.info(f"Agent {self.agent_id} reset to healthy homeostasis baseline.")

    def stop(self):
        self.running = False

if __name__ == "__main__":
    agent_id = os.getenv("AGENT_ID", sys.argv[1] if len(sys.argv) > 1 else "node-alpha")
    orch_url = os.getenv("ORCHESTRATOR_URL", "ws://localhost:8000/ws")
    agent = ImmuneAgent(agent_id=agent_id, orchestrator_url=orch_url)
    _health_agent = agent

    async def run_agent_service():
        health_server = uvicorn.Server(uvicorn.Config(
            agent_health_app,
            host="0.0.0.0",
            port=int(os.getenv("AGENT_HEALTH_PORT", "8100")),
            log_level="warning",
        ))
        await asyncio.gather(agent.start(), health_server.serve())

    try:
        asyncio.run(run_agent_service())
    except KeyboardInterrupt:
        agent.stop()
