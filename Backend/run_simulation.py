"""
IMMUNE-NET Local Swarm Simulation Runner.
Launches the Central Orchestrator and all 8 endpoint agents concurrently in a single Python runtime.
Allows seamless local execution on Windows without requiring Docker.
"""

import os
import sys

# Windows consoles default to cp1252, which cannot encode the em-dashes and
# unicode arrows used across backend messages. Force UTF-8 on stdout/stderr so
# the swarm never crashes while logging (e.g. when launched with redirection).
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Ensure backend root directory is on sys.path regardless of CWD
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import asyncio
import logging
import socket
import argparse
import uvicorn

from orchestrator.app import app
from agent.agent import ImmuneAgent
from common.nodes import DEFAULT_NODE_IDS

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s :: %(name)s :: %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("simulation.runner")

def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0

async def run_swarm(port: int = 8000):
    if is_port_in_use(port):
        logger.error(
            f"\n[PORT CONFLICT] Port {port} is already in use by another process!\n"
            f"  - If another IMMUNE-NET instance is running, please close it first, or\n"
            f"  - Run with a different port: python run_simulation.py --port {port+1}\n"
        )
        sys.exit(1)

    # 1. Configure Uvicorn Web Server for Orchestrator
    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=port,
        log_level="warning",
        access_log=False
    )
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())

    # Wait 1.5s for orchestrator server to bind
    logger.info(f"Starting Central Orchestrator on http://localhost:{port} & ws://localhost:{port}/ws...")
    await asyncio.sleep(1.5)

    # 2. Launch all 8 Swarm Agents concurrently
    agent_instances = []
    agent_tasks = []

    logger.info(f"Deploying {len(DEFAULT_NODE_IDS)} Autonomous Endpoint Agents across swarm mesh...")
    for node_id in DEFAULT_NODE_IDS:
        agent = ImmuneAgent(agent_id=node_id, orchestrator_url=f"ws://127.0.0.1:{port}/ws")
        agent_instances.append(agent)
        agent_tasks.append(asyncio.create_task(agent.start()))

    logger.info("================================================================================")
    logger.info("IMMUNE-NET Bio-Autonomous Security Mesh is ACTIVE!")
    logger.info(f"  Orchestrator REST & WebSocket: ws://localhost:{port}/ws")
    logger.info(f"  Frontend Dashboard: http://localhost:5173 (toggle 'Live WS' in header)")
    logger.info(f"  Active Agents ({len(agent_instances)}): {', '.join(DEFAULT_NODE_IDS)}")
    logger.info("================================================================================")

    try:
        # Keep running until cancelled
        await asyncio.gather(server_task, *agent_tasks)
    except (asyncio.CancelledError, KeyboardInterrupt):
        logger.info("Stopping simulation...")
        for a in agent_instances:
            a.stop()
        server.should_exit = True
        await server_task

def main():
    parser = argparse.ArgumentParser(description="IMMUNE-NET Local Swarm Simulation Runner")
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "8000")), help="Orchestrator port (default: 8000)")
    args = parser.parse_args()

    try:
        asyncio.run(run_swarm(port=args.port))
    except KeyboardInterrupt:
        logger.info("IMMUNE-NET simulation stopped by user.")

if __name__ == "__main__":
    main()
