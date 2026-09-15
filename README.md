IMMUNE-NET — Bio-Autonomous Cyber-Defense Mesh
Team
Team name: 404 Founder
Track: AI
Lead: Manan Khunt - manankhunt999@gmail.com
Members:
Arpit Padya
Adharsh Nanera
Jugal Mehta 

Problem Statement

Modern security operations centers rely on endpoint detection and response (EDR) tools that treat every host in isolation: each agent detects anomalies locally, but there is no fast, automatic way for the fleet to "learn" from an attack on one node and immediately protect every other node. This leaves organizations repeatedly exposed to the same attack pattern across different hosts, and forces human analysts to manually correlate signals, contain hosts, and write up incident briefings — a slow process that delays containment and burns analyst time during active incidents.

Solution

IMMUNE-NET reframes an EDR swarm as a living immune system. Lightweight edge agents act as innate immunity, using Isolation-Forest anomaly scoring on telemetry to flag suspicious behavior. A central FastAPI orchestrator acts as adaptive immunity: it correlates signals, confirms threats, maps them to MITRE ATT&CK, and quarantines the affected host. Once a threat is confirmed, the orchestrator synthesizes a cryptographically HMAC-signed digital antibody and broadcasts it across the entire mesh over WebSocket — giving every other node herd immunity against the same attack, sub-2ms, without human intervention. Antibodies persist in SQLite so the swarm's "immune memory" survives restarts. A React/Tailwind SOC dashboard visualizes the mesh live, and an IBM Bob MCP analyst server exposes threat-intelligence tooling so Bob can query the swarm, explain incidents, and generate executive BLUF (Bottom Line Up Front) briefings in natural language.

Key Features
8-node micro-segmentation swarm (Cortex Gateway, Thymus Auth, Medulla Vault, Artery Pay, Myelin Worker, Synapse DNS, Marrow Storage, Lymph Telemetry) plus a passive honeypot decoy (node-Ψ) with scenario profiles for cryptominer, port scan, C2 beacon, and worm attacks
Adaptive correlation engine that confirms threats, maps them to MITRE ATT&CK, and ranks top-3 likely APT groups via cosine similarity (APT attribution/fingerprinting)
Signed digital antibodies — HMAC-SHA256 over a canonical JSON payload (threat type, detection signature, eBPF rule, MITRE mapping) — broadcast mesh-wide for instant herd immunity, with expiring/decaying confidence and 60-minute re-vaccination sweeps
Blast-radius prediction for lateral-movement modeling, plus automatic quarantine/unfence of compromised nodes
IBM Bob MCP integration — a JSON-RPC 2.0 /mcp server exposing threat-intel tools so Bob can chat with the live swarm, explain incidents, and generate BLUF briefings
Live SOC HUD — a React/Vite/Tailwind "hacker terminal" dashboard (Matrix-rain themed) with real-time node topology, antibody library, honeypot log, and Bob chat, driven by REST polling + WebSocket events
Tech Stack
Backend: Python, FastAPI, uvicorn, WebSockets, SQLite, Isolation Forest (scikit-learn-style anomaly detection), HMAC-SHA256 signing
Frontend: React 18, Vite, Tailwind CSS, Zustand (state), HashRouter
AI / IBM tech: IBM Bob MCP server (JSON-RPC 2.0) for conversational threat analysis and briefings
Other: Docker Compose (optional full-stack run), MITRE ATT&CK mapping
How to Run
bash
# Backend (orchestrator + 8 agents)
cd backend && python -u run_simulation.py --port 8000

# Frontend dev server
cd frontend && npm install && npm run dev      # http://localhost:5173

# One-shot demo narrative (auto-starts backend if not running)
cd backend && python demo.py

# Acceptance / benchmark suite (starts its own orchestrator on :8001)
cd backend && python acceptance_test.py

# Full stack via Docker
cd backend && docker compose up --build

See docs/setup-guide.md for prerequisites, environment variables, and troubleshooting.

Demo
Video: [demo video URL — see demo/demo-video-link.txt]
Live demo: [live demo URL, or "NOT DEPLOYED" — see demo/live-demo-url.txt]
Screenshots: see demo/screenshots/
Known Limitations
Demo/local run defaults to a single-machine simulation (8 in-process agents); true multi-host deployment has not been load-tested.
SQLite is used for immune memory persistence, which is fine for the hackathon scale but would need a production-grade store (e.g., Postgres) for real fleets.
APT attribution is a cosine-similarity heuristic over MITRE mappings, not a full threat-intel feed integration.
[Add any other honest gaps here]
What We're Most Proud Of

The digital-antibody mechanism: a confirmed threat on one node is cryptographically signed and pushed to the entire swarm in real time, so a repeat attack against a different node is blocked automatically in under 2ms — true herd immunity rather than per-host remediation. Combined with the IBM Bob MCP integration, an analyst can ask Bob about the state of the swarm in plain language and get back a grounded, live BLUF briefing.
