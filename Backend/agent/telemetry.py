"""Phase telemetry frame generator with deterministic seeded noise."""

import random
from dataclasses import dataclass


@dataclass
class TelemetryFrame:
    cpu_pct: float
    mem_pct: float
    net_conns_per_sec: float
    syn_burst_ratio: float
    syscalls_per_min: float
    auth_failures: int
    file_ops_per_min: float
    processes: list[str]


class TelemetryGenerator:
    def __init__(self, seed: int | None = None):
        self.random = random.Random(seed)

    def healthy(self) -> TelemetryFrame:
        return TelemetryFrame(
            cpu_pct=round(self.random.gauss(24, 3), 2),
            mem_pct=round(self.random.gauss(40, 4), 2),
            net_conns_per_sec=round(self.random.gauss(3, 0.5), 2),
            syn_burst_ratio=round(max(0, self.random.gauss(0.05, 0.02)), 3),
            syscalls_per_min=round(self.random.gauss(850, 60), 2),
            auth_failures=max(0, int(self.random.gauss(1, 1))),
            file_ops_per_min=round(self.random.gauss(120, 15), 2),
            processes=["systemd", "node_service"],
        )
