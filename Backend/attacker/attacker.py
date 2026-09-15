"""
IMMUNE-NET Scripted Attacker Engine.
Executes reproducible, deterministic attack scenarios for the 4 hackathon test cases.
Supports first-attack and repeat-attack validation.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import argparse
import asyncio
import json
import logging
import time
import httpx
from typing import Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (attacker): %(message)s")
logger = logging.getLogger("attacker")

SCENARIO_ALIAS_MAP = {
    "crypto_ransomware": "cryptominer",
    "cryptominer": "cryptominer",
    "syn_cytokine_flood": "port_scan",
    "port_scan": "port_scan",
    "exfil_parasite": "c2_beacon",
    "c2_beacon": "c2_beacon",
    "kernel_blight": "worm",
    "worm": "worm",
}

SCENARIOS = {
    "cryptominer": {
        "name": "CryptoLock-X (Cryptomining & Ransomware)",
        "description": "Spawns high-entropy crypto miner processes driving CPU > 90%",
        "default_target": "node-beta",
        "secondary_target": "node-gamma",
    },
    "port_scan": {
        "name": "SynFlood-Cytokine (Port Scan / DDoS Probe)",
        "description": "Rapid multi-port sweep across internal network nodes",
        "default_target": "node-alpha",
        "secondary_target": "node-delta",
    },
    "c2_beacon": {
        "name": "ExfilParasite-Zero (C2 Beacon & Secret Exfiltration)",
        "description": "Periodic outbound command-and-control communication",
        "default_target": "node-gamma",
        "secondary_target": "node-epsilon",
    },
    "worm": {
        "name": "KernelBlight-Worm (Lateral Propagation)",
        "description": "Self-replicating infection attempting peer-to-peer cluster traversal",
        "default_target": "node-delta",
        "secondary_target": "node-zeta",
    },
}

class ScriptedAttacker:
    def __init__(self, orchestrator_http: str = "http://localhost:8000"):
        self.orchestrator_http = orchestrator_http

    async def launch_attack(
        self,
        scenario: str = "cryptominer",
        target: Optional[str] = None,
        mode: str = "first_attack"
    ) -> Dict[str, Any]:
        """
        Execute deterministic attack scenario against target agent.
        """
        scenario = SCENARIO_ALIAS_MAP.get(scenario, scenario)
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario '{scenario}'. Choose from {list(SCENARIOS.keys())}")

        spec = SCENARIOS[scenario]
        target_node = target or (spec["secondary_target"] if mode == "repeat_attack" else spec["default_target"])

        logger.info(f"==> Launching {mode.upper()} [{spec['name']}] against {target_node}...")

        payload = {
            "target_node": target_node,
            "scenario": scenario,
            "mode": mode
        }

        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{self.orchestrator_http}/api/demo/attack",
                    json=payload,
                    timeout=10.0
                )
                result = resp.json()
                logger.info(f"<== Attack dispatched to orchestrator: {result}")
                return result
            except Exception as e:
                logger.error(f"Failed to trigger attack via orchestrator: {e}")
                return {"status": "error", "error": str(e)}

    async def run_scenario_suite(self):
        """Run all 4 scenarios in sequence to demonstrate complete coverage."""
        logger.info("Starting Full 4-Scenario Demonstrator Suite...")
        for sc in SCENARIOS:
            logger.info(f"\n--------------------------------------------------")
            logger.info(f"DEMO SCENARIO: {sc}")
            logger.info(f"--------------------------------------------------")
            # Step 1: First attack on initial agent
            await self.launch_attack(scenario=sc, mode="first_attack")
            await asyncio.sleep(4.0)

            # Step 2: Repeat attack on secondary agent (proves swarm immunity)
            await self.launch_attack(scenario=sc, mode="repeat_attack")
            await asyncio.sleep(3.0)

def main():
    parser = argparse.ArgumentParser(description="IMMUNE-NET Scripted Attacker")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()), default="cryptominer", help="Attack scenario")
    parser.add_argument("--target", default=None, help="Target agent ID (e.g. node-beta)")
    parser.add_argument("--mode", choices=["first_attack", "repeat_attack", "suite"], default="first_attack", help="Execution mode")
    parser.add_argument("--orchestrator", default="http://localhost:8000", help="Orchestrator HTTP base URL")

    args = parser.parse_args()
    attacker = ScriptedAttacker(orchestrator_http=args.orchestrator)

    if args.mode == "suite":
        asyncio.run(attacker.run_scenario_suite())
    else:
        asyncio.run(attacker.launch_attack(scenario=args.scenario, target=args.target, mode=args.mode))

if __name__ == "__main__":
    main()
