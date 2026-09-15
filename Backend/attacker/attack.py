"""HTTP driver for deterministic IMMUNE-NET scenarios."""

import httpx

SCENARIOS = ("cryptominer", "port_scan", "c2_beacon", "worm_ravage")


def run_attack(base_url: str, target: str, scenario: str, timeout: float = 10.0) -> dict:
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    response = httpx.post(
        f"{base_url.rstrip('/')}/inject",
        json={"agent_id": target, "scenario_id": scenario, "process": "systemd"},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()
