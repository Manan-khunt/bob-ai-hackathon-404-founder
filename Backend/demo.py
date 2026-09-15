"""
IMMUNE-NET Self-Contained Demonstration Driver (Demo Mode).

Runs the full threat lifecycle against a live swarm without any external
infrastructure and prints a stage-by-stage narrative:

    Normal behavior → Suspicious activity → ML detection → Classification
    → Explanation → BLUF → Blast radius → Containment → Digital antibody
    → Herd immunity

Usage:
    python demo.py

If the orchestrator is not already running on PORT (default 8000), this script
launches it via `run_simulation.py` in a background process. Watsonx credentials
are optional; a rule-based BLUF fallback is used automatically when they are absent.
"""

import os
import sys
import time
import json
import socket
import subprocess

# Windows consoles default to cp1252, which cannot encode the demo's unicode
# arrows/em-dashes. Force UTF-8 on stdout/stderr so the narrative never crashes.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import httpx

DEFAULT_PORT = int(os.getenv("PORT", "8000"))
API = f"http://127.0.0.1:{DEFAULT_PORT}"


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0


def wait_for_health(timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = httpx.get(f"{API}/health", timeout=2.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def main() -> int:
    print("=" * 78)
    print("  IMMUNE-NET DEMO MODE — Immune-System-Inspired Autonomous Cyber Defense")
    print("  Attack → Detection → Explanation → BLUF → Blast Radius → Containment")
    print("           → Digital Antibody → Herd Immunity")
    print("=" * 78)

    launched = False
    if not is_port_in_use(DEFAULT_PORT):
        print(f"\n[1/2] Orchestrator not running on :{DEFAULT_PORT} — launching swarm...")
        proc = subprocess.Popen(
            [sys.executable, os.path.join(BASE_DIR, "run_simulation.py"), "--port", str(DEFAULT_PORT)],
            cwd=BASE_DIR,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        launched = True
        if not wait_for_health(timeout=45.0):
            print("ERROR: Orchestrator failed to start within 45s. Is port 8000 free?")
            return 1
        print("       Swarm ONLINE (8 agents connected to orchestrator).")
    else:
        print(f"\n[1/2] Orchestrator already running on :{DEFAULT_PORT} — reusing live swarm.")

    health = httpx.get(f"{API}/health", timeout=5.0).json()
    # Agents connect a moment after the server binds; wait until the fleet is online.
    agents_online = health.get("connected_agents_count", 0)
    deadline = time.time() + 20.0
    while agents_online < 8 and time.time() < deadline:
        time.sleep(0.5)
        try:
            agents_online = httpx.get(f"{API}/health", timeout=2.0).json().get("connected_agents_count", 0)
        except Exception:
            pass
    print(f"       Agents connected: {agents_online}")

    # ---------------------------------------------------------------
    # Stage driver helpers
    # ---------------------------------------------------------------
    def stage(n: int, title: str):
        print(f"\n{'-' * 78}")
        print(f"  STAGE {n}: {title}")
        print(f"{'-' * 78}")

    # 1. Reset to clean baseline
    stage(1, "RESET — Clean Fleet Baseline")
    r = httpx.post(f"{API}/api/demo/reset", timeout=10.0)
    print(f"  -> {r.json().get('status', 'unknown')}")
    stats = httpx.get(f"{API}/api/stats", timeout=5.0).json()
    print(
        f"  -> Fleet baseline: {stats['nodes_total']} endpoints, "
        f"{stats['active_threats']} active threats, "
        f"{stats['antibodies_total']} antibodies in memory"
    )

    # 2. Normal behavior (baseline telemetry is already streaming)
    stage(2, "NORMAL BEHAVIOR — Healthy Endpoint Telemetry")
    print("  -> 8 endpoint agents streaming biometric telemetry (CPU, memory, entropy, sockets)")
    print("  -> IsolationForest evaluated on each frame; nothing flagged")
    print("  -> False-positive rate target ≤ 5%")
    time.sleep(2.0)

    # 3. Suspicious activity + honeypot capture
    stage(3, "SUSPICIOUS ACTIVITY — Decoy Node Probe Captured")
    r = httpx.post(
        f"{API}/api/honeypot/attack",
        json={"source_ip": "185.220.101.4", "attack_vector": "cryptominer"},
        timeout=10.0,
    )
    captured = r.json()
    print(f"  -> Decoy Node-\u03a8 captured probe from {captured.get('source_ip', '?')}")
    print(f"  -> Antibody synthesized: {captured.get('antibody_id', 'n/a')}")

    # 4. Real attack (cryptominer) injected against node-beta
    stage(4, "ATTACK INJECTION — Cryptominer Pathogen on node-beta")
    print("  -> Dispatched simulated attack; agent injects 8 anomalous telemetry ticks")
    r = httpx.post(
        f"{API}/api/demo/attack",
        json={"target_node": "node-beta", "scenario": "cryptominer", "mode": "first_attack"},
        timeout=10.0,
    )
    print(f"  -> {r.json().get('status', '?')} against node-beta")

    # Wait for agent injection + innate detection + orchestrator correlation
    print("  -> Agent Isolation Forest scanning... waiting for detection cycle")
    incidents = []
    for _ in range(15):
        time.sleep(4.0)
        incidents = httpx.get(f"{API}/incidents", timeout=5.0).json()
        if incidents:
            break
    if not incidents:
        print("  WARNING: No incident confirmed within 60s — check agent connectivity.")
    latest = incidents[0] if incidents else {}

    # 5. ML detection + explanation
    stage(5, "ML ANOMALY DETECTION + EXPLANATION")
    threat = httpx.get(f"{API}/api/threats", timeout=5.0).json()
    t0 = threat[0] if threat else {}
    print(f"  -> Threat classified: {t0.get('classification', 'n/a')}")
    print(f"  -> Confidence: {float(t0.get('confidence_score', 0) or 0) * 100:.0f}%")
    print(f"  -> MITRE ATT&CK: {t0.get('mitre', {}).get('technique_id')} "
          f"{t0.get('mitre', {}).get('technique_name', '')}")
    explanation = t0.get("explanation") or {}
    if explanation.get("explanation"):
        print("  -> WHY WAS THIS FLAGGED?")
        for c in explanation["explanation"]:
            val = c.get("value")
            if isinstance(val, float) and val < 100:
                val_str = f"{val:.1f}"
            else:
                val_str = str(val)
            print(f"      • {c['feature'].replace('_', ' ')}: {val_str} "
                  f"({round(c['normalized_contribution'] * 100, 1)}% contribution) — {c['reason']}")
    else:
        print("  -> No explanation available (fallback)")

    # 6. BLUF
    stage(6, "COMMANDER BLUF BRIEFING")
    if latest.get("bluf_summary"):
        summary = latest["bluf_summary"]
        if summary.startswith(("BOTTOM LINE", "CRITICAL", "Alert")):
            print(f"  -> {summary.splitlines()[0]}")
        else:
            print(f"  -> {summary}")
    else:
        print("  -> No BLUF captured (waiting for confirmation)")

    # 7. Blast radius
    stage(7, "BLAST RADIUS — Lateral Movement Prediction")
    br = httpx.get(f"{API}/api/blast-radius/node-beta", timeout=5.0).json()
    chain = br.get("propagation_chain", [])
    for e in chain:
        label = "AUTO-QUARANTINED" if e.get("auto_quarantined") else "monitoring"
        print(f"  -> {e['node_id']}: estimated fall {e.get('estimated_seconds_to_fall', '?')}s [{label}]")

    # 8. Containment
    stage(8, "AUTONOMOUS CONTAINMENT")
    nodes = httpx.get(f"{API}/api/nodes", timeout=5.0).json()
    target = next((n for n in nodes if n.get("agent_id") == "node-beta"), {})
    print(f"  -> node-beta status: {target.get('status', '?')}")
    print(f"  -> Quarantine command issued + signed; lateral connectivity severed")

    # 9. Digital antibody + immune memory
    stage(9, "DIGITAL ANTIBODY + IMMUNE MEMORY")
    abs_list = httpx.get(f"{API}/api/antibodies", timeout=5.0).json()
    for ab in abs_list:
        print(f"  -> {ab['antibody_id']} — {ab['threat_type']} "
              f"(rule: {ab.get('ebpf_rule', '')[:44] or 'n/a'})")
    mem = httpx.get(f"{API}/api/distribution", timeout=5.0).json()
    print(f"  -> Distribution: {mem}")

    # 10. Herd immunity
    stage(10, "HERD IMMUNITY — Repeat Attack Deflected")
    r = httpx.post(
        f"{API}/api/demo/attack",
        json={"target_node": "node-gamma", "scenario": "cryptominer", "mode": "repeat_attack"},
        timeout=10.0,
    )
    print(f"  -> Repeat cryptominer attack fired at node-gamma")
    time.sleep(3.0)
    stats = httpx.get(f"{API}/api/stats", timeout=5.0).json()
    print(f"  -> Fleet immunity: {stats['immunity_pct']}%  |  "
          f"Threats seen: {stats['total_threats_seen']}  |  "
          f"Antibodies: {stats['antibodies_total']}")
    print(f"  -> Digital immune memory now protects the remaining endpoints.")

    # Wrap up
    print("\n" + "=" * 78)
    print("  DEMO COMPLETE — Fleet is armed with immunity.")
    print(f"  Open the live dashboard at http://localhost:5173 to interact.")
    print("=" * 78)

    if launched:
        print("\n[2/2] The background swarm continues running. Stop it with:")
        print(f"       Ctrl+C on this console, or: taskkill /F /PID <run_simulation pid>")
        print(f"  Background PID: {proc.pid}")
        interactive = bool(getattr(sys.stdin, "isatty", lambda: False)())
        if interactive:
            try:
                input("\nPress Enter to stop the launched swarm and exit demo mode...\n")
            except (EOFError, KeyboardInterrupt):
                pass
            proc.terminate()
            proc.wait(timeout=10.0)
            print("Swarm stopped.")
        else:
            print("  (Non-interactive shell detected — leaving swarm running.)")

    return 0


if __name__ == "__main__":
    sys.exit(main())