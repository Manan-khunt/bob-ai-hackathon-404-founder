IMMUNE-NET
Autonomous Threat Correlation & Response System — inspired by biological immunity
Team: 404 Founder | Track: AI | Members: Manan, Jugal, Adharsh, Arpit
📌 Problem Statement
Security teams are flooded with thousands of alerts daily from distributed sensors and endpoints, arriving in inconsistent formats. No human team can review them all in time — missing a real threat is catastrophic, and chasing false positives wastes critical response time. Once a threat is confirmed, it still needs to be mapped to a recognized threat framework and summarized clearly enough for a decision-maker to act on in minutes, not hours.
💡 Proposed Solution
IMMUNE-NET is a decentralized, self-healing network security simulator inspired by biological immunity. Eight simulated agents stream behavioral telemetry to a central orchestrator, which uses an Isolation Forest model to detect and confirm genuine threats with a weighted confidence score. Once confirmed, the affected node is automatically quarantined, a signed "antibody" signature of the attack is generated, mapped to its MITRE ATT&CK technique, and broadcast in real time to every other node — so the same attack is blocked locally anywhere else on the network, instantly, with zero orchestrator round-trip and zero human intervention required for the block itself. Every incident is also compiled into a structured BLUF (Bottom Line Up Front) summary with a hardening recommendation, routed to the responsible node owner with automatic escalation if unacknowledged.
🖥️ Project / Application
A working full-stack simulator:
Backend: FastAPI orchestrator + 8 simulated endpoint agents (Python, scikit-learn, WebSockets, SQLite)
Frontend: React/Vite dashboard — live network topology, attack trigger controls, admin alerts panel, explainability panel
Run locally via:
Bash
Dashboard: http://localhost:5173/ | API docs: http://localhost:8000/docs
💻 Source Code
Modular Python backend: detector.py, quarantine.py, antibody.py, mitre_mapping.py, bluf.py, recommend.py, memory.py, broadcast.py. React frontend: NetworkTopology.jsx, AdminAlertsPanel.jsx, ExplainabilityPanel.jsx, AttackTriggerDeck.jsx. All source lives under src/backend/ and src/frontend/.
📄 Documentation
Full docs in docs/:
problem-statement.md
solution-overview.md
architecture.md — includes Mermaid diagram + component table
setup-guide.md — tested end-to-end
🎬 Demo
See demo/demo-video-link.txt for the full walkthrough: system startup → first attack detected/quarantined → antibody broadcast → repeat attack blocked instantly on a different node.
📸 Screenshots
See demo/screenshots/:
Healthy network topology
Attack detected + quarantine + admin alert
Antibody broadcast propagation
Repeat attack blocked instantly
BLUF summary + MITRE ATT&CK panel
📊 Presentation
See presentation/slides.pdf — Problem → Solution → Architecture/Demo → IBM Technology Integration → Impact & Future Scope.
Tech Stack
Backend: Python 3.x, FastAPI, WebSockets, SQLite, scikit-learn (IsolationForest), Pydantic, Docker Compose, pytest
Frontend: React, Vite, JavaScript/JSX, Lucide icons
IBM Technology: watsonx.ai (optional — enriches threat narratives and BLUF detail; system falls back to deterministic logic if not configured)
Known Limitations
This is a controlled hackathon simulator using synthetic telemetry and scripted attack scenarios — it is not a production endpoint-security replacement. The watsonx.ai layer is optional and the system is fully functional without it.
What We're Most Proud Of
The core immune-response loop: a first attack is contained in seconds, and every subsequent identical attack anywhere else on the network is blocked locally, instantly, with zero orchestrator round-trip — demonstrated live with a 100% repeat-attack block rate, backed by SQLite persistence so immunity survives a full restart.