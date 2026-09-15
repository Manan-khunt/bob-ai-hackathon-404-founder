"""
Telemetry Generator for IMMUNE-NET Agents.
Produces natural baseline system telemetry and supports attack payload injection.
"""

import random
from typing import Optional
from common.schemas import TelemetryEvent, generate_uuid, utc_iso_now

class TelemetryGenerator:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.active_attack: Optional[str] = None
        self.attack_duration_ticks: int = 0

    def inject_attack(self, scenario: str, ticks: int = 5):
        """Simulate malicious telemetry injection."""
        self.active_attack = scenario
        self.attack_duration_ticks = ticks

    def clear_attack(self):
        """Restore baseline normal telemetry generation."""
        self.active_attack = None
        self.attack_duration_ticks = 0

    def generate(self) -> TelemetryEvent:
        """Produce next telemetry window record."""
        if self.active_attack and self.attack_duration_ticks > 0:
            self.attack_duration_ticks -= 1
            scenario = self.active_attack
            if self.attack_duration_ticks == 0:
                self.active_attack = None

            if scenario == "cryptominer":
                return TelemetryEvent(
                    agent_id=self.agent_id,
                    process="xmrig_crypto_miner",
                    cpu_percent=round(random.uniform(85.0, 96.5), 1),
                    memory_percent=round(random.uniform(60.0, 78.0), 1),
                    network_connections=random.randint(15, 30),
                    bytes_sent=random.randint(8000, 25000),
                    bytes_received=random.randint(12000, 45000),
                    destination="pool.monero.org:3333",
                    connection_rate=round(random.uniform(2.0, 5.0), 1),
                    file_activity=random.randint(45, 90),
                    scenario_id="cryptominer",
                    entropy=round(random.uniform(0.88, 0.96), 2)
                )

            elif scenario == "port_scan":
                return TelemetryEvent(
                    agent_id=self.agent_id,
                    process="syn_scan_probe",
                    cpu_percent=round(random.uniform(25.0, 45.0), 1),
                    memory_percent=round(random.uniform(35.0, 50.0), 1),
                    network_connections=random.randint(85, 160),
                    bytes_sent=random.randint(35000, 80000),
                    bytes_received=random.randint(4000, 10000),
                    destination=f"10.0.1.{random.randint(1, 50)}:{random.randint(20, 8080)}",
                    connection_rate=round(random.uniform(22.0, 38.0), 1),
                    file_activity=random.randint(2, 8),
                    scenario_id="port_scan",
                    entropy=round(random.uniform(0.35, 0.55), 2)
                )

            elif scenario == "c2_beacon":
                return TelemetryEvent(
                    agent_id=self.agent_id,
                    process="exfil_parasite_agent",
                    cpu_percent=round(random.uniform(20.0, 38.0), 1),
                    memory_percent=round(random.uniform(30.0, 45.0), 1),
                    network_connections=random.randint(10, 20),
                    bytes_sent=random.randint(40000, 95000),
                    bytes_received=random.randint(2000, 5000),
                    destination="evil-c2.bio.net:443",
                    connection_rate=round(random.uniform(1.0, 2.5), 1),
                    file_activity=random.randint(10, 25),
                    scenario_id="c2_beacon",
                    entropy=round(random.uniform(0.72, 0.85), 2)
                )

            elif scenario == "worm":
                return TelemetryEvent(
                    agent_id=self.agent_id,
                    process="kernel_blight_worm",
                    cpu_percent=round(random.uniform(50.0, 75.0), 1),
                    memory_percent=round(random.uniform(55.0, 70.0), 1),
                    network_connections=random.randint(40, 75),
                    bytes_sent=random.randint(25000, 60000),
                    bytes_received=random.randint(15000, 35000),
                    destination=f"10.0.1.{random.choice([15, 20, 25, 30, 35])}:22",
                    connection_rate=round(random.uniform(8.0, 16.0), 1),
                    file_activity=random.randint(30, 60),
                    scenario_id="worm",
                    entropy=round(random.uniform(0.65, 0.80), 2)
                )

        # Natural baseline telemetry
        return TelemetryEvent(
            agent_id=self.agent_id,
            process="node_service",
            cpu_percent=round(random.uniform(12.0, 26.0), 1),
            memory_percent=round(random.uniform(28.0, 44.0), 1),
            network_connections=random.randint(8, 22),
            bytes_sent=random.randint(800, 2800),
            bytes_received=random.randint(1500, 4800),
            destination="10.0.1.1:443",
            connection_rate=round(random.uniform(1.2, 3.8), 1),
            file_activity=random.randint(2, 9),
            scenario_id=None,
            entropy=round(random.uniform(0.08, 0.18), 2)
        )
