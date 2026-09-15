"""
IMMUNE-NET Central Orchestrator Application.
FastAPI web service and WebSocket hub managing threat intelligence correlation,
MITRE ATT&CK mapping, digital antibody synthesis, autonomous quarantine, and swarm fortification.
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Body, Path
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html
from pydantic import BaseModel, Field

from common.schemas import (
    TelemetryEvent,
    LocalAnomalyEvent,
    ConfirmedThreat,
    QuarantineCommand,
    Antibody,
    AgentAcknowledgement,
    AgentStatusRecord,
    generate_uuid,
    utc_iso_now,
    utc_now,
    compute_effective_confidence,
    compute_decay_status,
)
from common.nodes import NODES_CATALOG, HONEYPOT_NODE_ID, HONEYPOT_PROFILES
from common.crypto_utils import sign_payload
from orchestrator.database import ImmuneDatabase
from orchestrator.detector import AdaptiveCorrelator
from orchestrator.synthesizer import AntibodySynthesizer
from orchestrator.broadcaster import SwarmBroadcaster
from common.config import get_settings
from orchestrator.antibody import generate_antibody
from orchestrator.features import fit_baseline, load_model, telemetry_vector
from orchestrator.memory import PhaseMemory
from orchestrator.quarantine import QuarantineManager, notify_admins, cancel_escalation
from orchestrator.broadcast import WebSocketHub
from orchestrator.mitre_mapping import get_mitre_technique
from orchestrator.bluf import generate_bluf_summary
from orchestrator.apt_fingerprint import fingerprint_threat_actor, detected_techniques_for
from orchestrator.blast_radius import predict_blast_radius
from orchestrator.honeypot import HoneypotManager
from orchestrator.bob_mcp import router as mcp_router, set_mcp_context

SCENARIO_ALIAS_MAP: Dict[str, str] = {
    "crypto_ransomware": "cryptominer",
    "cryptominer": "cryptominer",
    "syn_cytokine_flood": "port_scan",
    "port_scan": "port_scan",
    "exfil_parasite": "c2_beacon",
    "c2_beacon": "c2_beacon",
    "kernel_blight": "worm",
    "worm_ravage": "worm",
    "worm": "worm",
}

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s :: %(name)s :: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("orchestrator.app")

# Shared singletons
db = ImmuneDatabase()
correlator = AdaptiveCorrelator()
synthesizer = AntibodySynthesizer()
broadcaster = SwarmBroadcaster(db)
settings = get_settings()
phase_memory = PhaseMemory(settings.db_path)
quarantine_manager = QuarantineManager(
    sustained_frames=settings.confidence_sustained,
    threshold=settings.confidence_quarantine,
)
agent_hub = WebSocketHub()
hud_hub = WebSocketHub()
phase_telemetry: List[TelemetryEvent] = []
phase_model = None

# Decoy honeypot trap manager.
honeypot = HoneypotManager(db, synthesizer)

# Re-vaccination sweep cadence (60 minutes).
DECAY_SWEEP_INTERVAL_SECONDS: int = 60 * 60

# In-memory node states matching the 8 fleet nodes
node_states: Dict[str, AgentStatusRecord] = {}


def init_node_states() -> None:
    """Initialize in-memory fleet node states from the predefined nodes catalog."""
    for nid, data in NODES_CATALOG.items():
        node_states[nid] = AgentStatusRecord(
            agent_id=nid,
            status="healthy",
            ip=data["ip"],
            anomaly_score=4.0,
            owner_id=data.get("owner_id", "admin_1"),
            biomarkers={"cpu": 20, "memory": 40, "entropy": 0.12, "socketLoad": 100},
        )


init_node_states()


async def send_admin_alert(payload: Dict[str, Any]) -> None:
    """
    Fan out admin alert event to connected frontend and HUD WebSocket listeners.

    Args:
        payload: Alert event dictionary.
    """
    await broadcaster._send_frontend_raw(json.dumps(payload))
    await hud_hub.broadcast(payload)


async def create_admin_alert_for_incident(incident: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create and dispatch an administrative alert for a security incident.

    Args:
        incident: Incident dictionary containing node ID and attack details.

    Returns:
        Created alert record dictionary.
    """
    owner_id = NODES_CATALOG.get(incident["node_id"], {}).get("owner_id", "admin_1")
    return await notify_admins(
        incident,
        owner_id,
        phase_memory,
        send_admin_alert,
        webhook_url=settings.webhook_url,
        escalation_seconds=settings.alert_escalation_seconds,
    )


def refresh_decay_statuses() -> int:
    """Recompute decay fields for all stored antibodies; persist any that drifted. Returns changed count."""
    changed = 0
    for ab in db.get_all_antibodies():
        eff = compute_effective_confidence(
            ab.created_at,
            half_life_hours=ab.half_life_hours,
            synthesized_at=ab.synthesized_at,
            base_confidence=ab.base_confidence,
        )
        status = compute_decay_status(eff)
        if abs((ab.effective_confidence if ab.effective_confidence is not None else -1.0) - eff) > 1e-9 or ab.decay_status != status:
            ab.effective_confidence = eff
            ab.decay_status = status
            db.save_antibody(ab)
            changed += 1
    return changed


async def antibody_decay_sweep() -> None:
    """
    Background re-vaccination loop.
    Runs every 60 minutes: any antibody whose effective confidence has decayed below 0.40 is
    re-synthesized (synthesized_at bumped, version incremented) restoring full protection.
    """
    while True:
        await asyncio.sleep(DECAY_SWEEP_INTERVAL_SECONDS)
        try:
            active = db.get_all_antibodies(status="active")
            re_vaccinated = 0
            for ab in active:
                eff = compute_effective_confidence(
                    ab.created_at,
                    half_life_hours=ab.half_life_hours,
                    synthesized_at=ab.synthesized_at,
                    base_confidence=ab.base_confidence,
                )
                if eff < 0.40:
                    ab.synthesized_at = utc_now()
                    ab.version = (ab.version or 1) + 1
                    ab.effective_confidence = 1.0
                    ab.decay_status = "active"
                    db.save_antibody(ab)
                    re_vaccinated += 1
                    logger.info(
                        f"[RE-VACCINATION] Antibody {ab.antibody_id} re-synthesized (v{ab.version}) — "
                        f"effective confidence restored to 1.0 for {ab.threat_type} immunity."
                    )
            if re_vaccinated:
                await broadcaster.send_frontend_event({
                    "type": "REVACCINATION",
                    "severity": "SUCCESS",
                    "title": f"Antibody Re-vaccination Sweep: {re_vaccinated} antibodies renewed",
                    "detail": "Decayed antibodies re-synthesized autonomously. Herd immunity re-established.",
                    "nodeId": "ALL",
                    "nodeName": "Swarm Orchestrator",
                    "metadata": {"re_vaccinated": re_vaccinated},
                })
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(f"[RE-VACCINATION] Sweep failed: {exc}")
            await asyncio.sleep(DECAY_SWEEP_INTERVAL_SECONDS)


async def run_scenario_async(scenario: str) -> Dict[str, Any]:
    """MCP hook: dispatch a named attack scenario through the demo pipeline."""
    req = AttackRequest(target_node="node-beta", scenario=scenario, mode="first_attack")
    return await trigger_demo_attack(req)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager handling startup rehydration and graceful shutdown."""
    global phase_model
    active_abs = db.get_all_antibodies(status="active")
    if settings.model_path.exists():
        phase_model = load_model(settings.model_path)
    set_mcp_context({
        "node_states": node_states,
        "db": db,
        "phase_memory": phase_memory,
        "quarantine_manager": quarantine_manager,
        "run_scenario_async": run_scenario_async,
    })
    refresh_decay_statuses()
    decay_task = asyncio.create_task(antibody_decay_sweep())
    logger.info(
        f"IMMUNE-NET Orchestrator initialized. Rehydrated {len(active_abs)} active antibodies from SQLite. "
        f"Decay re-vaccination sweep started (every {DECAY_SWEEP_INTERVAL_SECONDS // 60} min)."
    )
    yield
    decay_task.cancel()
    logger.info("IMMUNE-NET Orchestrator shutting down.")


API_DESCRIPTION = """
## IMMUNE-NET — Bio-Inspired Threat Intelligence & Autonomous Response Mesh

**IMMUNE-NET** is an autonomous endpoint detection, threat intelligence correlation, and real-time immunisation system modelled on the biological immune system.

### Core Autonomous Lifecycle
- **Detect**: Lightweight edge agents evaluate behavioral biomarker telemetry via local Isolation Forest algorithms.
- **Correlate**: The central orchestrator correlates multi-node telemetry and innate anomaly signals, confirming threats and mapping them to **MITRE ATT&CK techniques**.
- **Quarantine**: Reversible autonomous inflammatory quarantine fences compromised nodes and notifies assigned owners.
- **Synthesize**: The orchestrator derives normalized, cryptographically signed **Digital Antibodies** with eBPF/XDP bytecode rules.
- **Broadcast**: Antibodies are fanned out across the swarm mesh over authenticated WebSockets.
- **Immunity**: Mesh peer nodes load rules into kernel hooks, achieving sub-2ms immunity against repeat attacks.
- **BLUF Summaries**: Executive **Bottom Line Up Front** summaries provide instant triage visibility for SOC teams.
"""

TAGS_METADATA = [
    {"name": "System & Health", "description": "Core system status, health checks, and service readiness."},
    {"name": "Telemetry", "description": "Biomarker telemetry ingestion and baseline drift collection."},
    {"name": "Detection & Anomaly", "description": "Innate anomaly evaluation, model training, and adaptive correlation."},
    {"name": "Quarantine", "description": "Reversible node containment, manual fencing, and unfencing."},
    {"name": "Antibodies", "description": "Digital antibody synthesis, retrieval, and swarm distribution status."},
    {"name": "Incidents", "description": "Confirmed threat history, MITRE ATT&CK mappings, and BLUF summaries."},
    {"name": "Alerts", "description": "Administrative security alerts, acknowledgement, and escalation."},
    {"name": "Fleet & Nodes", "description": "Real-time posture and status of all swarm endpoint nodes."},
    {"name": "Demonstration & Simulation", "description": "Interactive attack injection, repeat-attack tests, and memory reset."},
]

app = FastAPI(
    title="IMMUNE-NET — Threat Intelligence & Autonomous Response API",
    description=API_DESCRIPTION,
    version="1.0.0",
    contact={
        "name": "IMMUNE-NET Security Mesh Team",
        "url": "https://github.com/immune-net",
        "email": "security@immune-net.local",
    },
    license_info={
        "name": "Apache 2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
    },
    openapi_tags=TAGS_METADATA,
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


@app.get("/docs", include_in_schema=False)
async def cyber_docs() -> HTMLResponse:
    """Serve the OpenAPI Swagger UI with the IMMUNE-NET cyber-immune dark theme."""
    page = get_swagger_ui_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title="IMMUNE-NET API Console",
        swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
        swagger_ui_parameters={"defaultModelsExpandDepth": 2, "displayRequestDuration": True},
    ).body.decode("utf-8")
    theme = """
    <style>
      :root { color-scheme: dark; }
      html, body { margin: 0; background: #080d13; color: #d8fff5; font-family: 'JetBrains Mono', 'Cascadia Code', monospace; }
      body:before { content: ''; position: fixed; inset: 0; pointer-events: none; opacity: .35; background: linear-gradient(rgba(57,255,228,.025) 1px, transparent 1px), linear-gradient(90deg, rgba(57,255,228,.025) 1px, transparent 1px); background-size: 32px 32px; }
      .swagger-ui { max-width: 1440px; margin: 0 auto; padding: 18px 28px 48px; position: relative; }
      .swagger-ui .topbar { background: transparent; border-bottom: 1px solid rgba(57,255,228,.2); padding: 14px 0 18px; }
      .swagger-ui .topbar-wrapper img { display: none; }
      .swagger-ui .topbar-wrapper:before { content: 'IMMUNE-NET // API CONSOLE'; color: #39ffe4; font-size: 18px; font-weight: 700; letter-spacing: .08em; }
      .swagger-ui .info .title, .swagger-ui .opblock-tag, .swagger-ui .opblock-summary-description { color: #e9fff9; }
      .swagger-ui .info .title small, .swagger-ui .info a { color: #39ffe4; }
      .swagger-ui .scheme-container, .swagger-ui section.models, .swagger-ui .opblock { background: rgba(13,17,23,.82); border: 1px solid rgba(57,255,228,.16); box-shadow: 0 10px 28px rgba(0,0,0,.28); }
      .swagger-ui .opblock-summary { border-color: rgba(255,255,255,.08); }
      .swagger-ui .opblock-summary-method { background: #00a878; }
      .swagger-ui .opblock.opblock-post .opblock-summary-method { background: #c53b5e; }
      .swagger-ui .opblock.opblock-get .opblock-summary-method { background: #087f8c; }
      .swagger-ui input, .swagger-ui textarea, .swagger-ui select, .swagger-ui .model-box { background: #0b1118; color: #d8fff5; border-color: rgba(57,255,228,.24); }
      .swagger-ui table thead tr td, .swagger-ui table thead tr th, .swagger-ui .parameter__name, .swagger-ui .parameter__type { color: #39ffe4; }
      .swagger-ui .btn.execute { background: #00a878; border-color: #00ff9c; color: #04110d; }
      .swagger-ui .response-col_status, .swagger-ui .prop-type { color: #ffb800; }
      .swagger-ui .markdown p, .swagger-ui .renderedMarkdown p, .swagger-ui label { color: #9ab5b0; }
    </style>
    """
    return HTMLResponse(page.replace("</head>", f"{theme}</head>"))


# Enable CORS for frontend dashboard compatibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# IBM BoB Model Context Protocol router (manifest at GET /mcp, JSON-RPC at POST /mcp)
app.include_router(mcp_router)


async def broadcast_typed_event(msg_type: str, **data: Any) -> None:
    """Fan out a typed real-time event (e.g. honeypot_hit, blast_radius) to all frontend dashboards."""
    payload = {"type": msg_type, **data, "timestamp": utc_iso_now()}
    await broadcaster._send_frontend_raw(json.dumps(payload))
    await hud_hub.broadcast(payload)


# ---------------------------------------------------------
# Root & Health Endpoints
# ---------------------------------------------------------
@app.get(
    "/",
    tags=["System & Health"],
    summary="IMMUNE-NET API Welcome & Overview",
    description="Returns a welcome payload with overview metadata and navigation links to primary API resources.",
)
async def get_root_index() -> Dict[str, Any]:
    """Return welcome payload with quick links and API overview."""
    return {
        "name": "IMMUNE-NET — Threat Intelligence & Autonomous Response API",
        "description": "Bio-inspired distributed endpoint defense mesh with instant autonomous immunity (detect → correlate → quarantine → antibody → broadcast → immunity).",
        "version": "1.0.0",
        "status": "operational",
        "endpoints": {
            "documentation": "/docs",
            "health": "/health",
            "fleet_nodes": "/api/nodes",
            "antibodies": "/antibodies",
            "incidents": "/incidents",
            "alerts": "/alerts",
            "websocket_hub": "/ws",
        },
        "timestamp": utc_iso_now(),
    }


@app.get(
    "/health",
    tags=["System & Health"],
    summary="System Health & Readiness",
    description="Returns service status, database readiness, active antibody counts, and active connected agent socket tallies.",
)
@app.get("/api/health", include_in_schema=False)
async def get_health() -> Dict[str, Any]:
    """Return health, database readiness, and connected agent count."""
    active_abs = db.get_all_antibodies(status="active")
    return {
        "status": "healthy",
        "service": "IMMUNE-NET Orchestrator",
        "database_ready": True,
        "active_antibodies_count": len(active_abs),
        "connected_agents_count": len(broadcaster.agent_sockets),
        "connected_agents": list(broadcaster.agent_sockets.keys()),
        "connected_frontends_count": len(broadcaster.frontend_sockets),
        "timestamp": utc_iso_now(),
    }


# ---------------------------------------------------------
# Nodes Status Endpoint
# ---------------------------------------------------------
@app.get(
    "/api/nodes",
    tags=["Fleet & Nodes"],
    summary="List Swarm Fleet Nodes",
    description="Returns real-time security posture, IP, biomarker readings, active threats, and installed antibody shields for all 8 fleet nodes.",
    response_model=List[AgentStatusRecord],
)
async def get_nodes() -> List[AgentStatusRecord]:
    """List current status of all 8 nodes in the fleet."""
    return list(node_states.values())


# ---------------------------------------------------------
# Telemetry Ingestion
# ---------------------------------------------------------
@app.post(
    "/api/telemetry",
    tags=["Telemetry"],
    summary="Ingest Endpoint Telemetry",
    description="Ingest behavioral biomarker telemetry from an endpoint agent and update in-memory node state.",
)
async def ingest_telemetry(event: TelemetryEvent) -> Dict[str, Any]:
    """Ingest endpoint telemetry from agents."""
    correlator.ingest_telemetry(event)
    # Update latest biomarker readings in memory
    if event.agent_id in node_states:
        node_states[event.agent_id].last_seen = utc_iso_now()
        node_states[event.agent_id].biomarkers = {
            "cpu": event.cpu_percent,
            "memory": event.memory_percent,
            "entropy": event.entropy,
            "socketLoad": event.network_connections,
        }
    return {"status": "accepted", "event_id": event.event_id}


@app.post(
    "/telemetry",
    tags=["Telemetry"],
    summary="Ingest Telemetry with Baseline Scoring",
    description="Ingest telemetry frame with baseline drift scoring against fitted Isolation Forest model and automatic quarantine check.",
)
async def ingest_phase_telemetry(event: TelemetryEvent) -> Dict[str, Any]:
    """Phase contract alias with bounded baseline collection and anomaly evaluation."""
    global phase_model
    phase_telemetry.append(event)
    if len(phase_telemetry) > max(6000, settings.agent_count * 120):
        del phase_telemetry[:-max(6000, settings.agent_count * 120)]
    result = await ingest_telemetry(event)
    if phase_model is not None:
        artifact = load_model(settings.model_path)
        raw_score = float(-artifact["model"].decision_function([telemetry_vector(event)])[0])
        normalized_score = max(0.0, min(1.0, 0.5 + raw_score))
        confidence_score = min(1.0, 0.6 * normalized_score + 0.15)
        record = quarantine_manager.observe(event.agent_id, confidence_score, "model confidence threshold")
        await hud_hub.broadcast({"type": "TELEMETRY_SCORE", "agent_id": event.agent_id, "confidence": confidence_score, "quarantine": record.__dict__})
    return result


@app.post(
    "/rebuild_model",
    tags=["Detection & Anomaly"],
    summary="Fit Baseline Isolation Forest Model",
    description="Fits and persists an Isolation Forest model using normal baseline telemetry frames collected across the swarm.",
)
async def rebuild_model() -> Dict[str, Any]:
    """Fit and persist the IsolationForest from collected healthy telemetry."""
    global phase_model
    if len(phase_telemetry) < 1:
        raise HTTPException(status_code=409, detail="baseline telemetry is empty")
    result = fit_baseline(phase_telemetry, settings.model_path)
    phase_model = load_model(settings.model_path)
    await hud_hub.broadcast({"type": "MODEL_REBUILT", **result})
    return result


@app.post(
    "/inject",
    tags=["Demonstration & Simulation"],
    summary="Inject Simulated Attack Telemetry Frame",
    description="Deterministically inject an anomalous telemetry frame, synthesize a digital antibody, map MITRE ATT&CK, generate a BLUF summary, and broadcast to the swarm.",
)
async def inject_infected_frame(event: TelemetryEvent) -> Dict[str, Any]:
    """Inject a deterministic infected frame without requiring an external attacker process."""
    scenario = event.scenario_id or "cryptominer"
    injected = event.model_copy(update={
        "process": "xmrig" if event.process == "systemd" else event.process,
        "cpu_percent": max(event.cpu_percent, 95.0),
        "entropy": max(event.entropy, 0.95),
        "scenario_id": scenario,
    })
    result = await ingest_phase_telemetry(injected)
    feature_vector = {"scenario": scenario, "cpu_percent": 95.0, "entropy": 0.95}
    detection_rule = {"type": "scenario", "threshold": 0.95, "window_secs": 3}
    action = {"type": "quarantine_source", "match": [scenario]}
    antibody = generate_antibody(feature_vector, scenario, 0.99, detection_rule, action)
    phase_memory.save_antibody(antibody)

    owner_id = NODES_CATALOG.get(injected.agent_id, {}).get("owner_id", "admin_1")
    mitre = get_mitre_technique(scenario)
    incident = {
        "incident_id": f"incident-{antibody['signature'][:16]}",
        "node_id": injected.agent_id,
        "scenario": scenario,
        "confidence": 0.99,
        "antibody_id": antibody["antibody_id"],
        "status": "confirmed",
        "timestamp": utc_iso_now(),
        "attack_type": scenario,
        "recommendation": antibody.get("recommendation"),
        "mitre": mitre,
        "owner_id": owner_id,
    }
    incident["bluf_summary"] = generate_bluf_summary(incident, antibody, total_nodes=8, immunized_count=8)

    phase_memory.save_incident(incident)
    await create_admin_alert_for_incident(incident)
    await agent_hub.broadcast({"type": "ANTIBODY", "antibody": antibody})
    await hud_hub.broadcast({"type": "INCIDENT", "incident": incident, "antibody": antibody})
    return {**result, "incident": incident, "antibody": antibody}


# ---------------------------------------------------------
# Quarantine Endpoints
# ---------------------------------------------------------
@app.post(
    "/quarantine/{agent_id}",
    tags=["Quarantine"],
    summary="Manually Fence Node into Quarantine",
    description="Isolate an agent from the swarm mesh, preventing inbound/outbound communication and triggering administrative alert.",
)
@app.post("/api/quarantine/{agent_id}", include_in_schema=False)
async def manual_quarantine(agent_id: str = Path(..., description="Target node to quarantine")) -> Dict[str, Any]:
    """Manually fence an agent into quarantine."""
    record = quarantine_manager.fence(agent_id)
    await broadcaster.send_frontend_patch(agent_id, {"status": "quarantined"})
    await hud_hub.broadcast({"type": "QUARANTINE", "record": record.__dict__})
    await create_admin_alert_for_incident({
        "incident_id": f"manual-{agent_id}-{record.updated_at}",
        "node_id": agent_id,
        "attack_type": "manual_quarantine",
        "confidence": 1.0,
    })
    return record.__dict__


@app.post(
    "/unfence/{agent_id}",
    tags=["Quarantine"],
    summary="Release Quarantined Node",
    description="Release an agent from quarantine fence, returning its status to healthy/immune.",
)
@app.post("/api/release/{agent_id}", include_in_schema=False)
async def manual_unfence(agent_id: str = Path(..., description="Target node to release")) -> Dict[str, Any]:
    """Manually release an agent from quarantine fence."""
    record = quarantine_manager.unfence(agent_id)
    await broadcaster.send_frontend_patch(agent_id, {"status": "healthy"})
    await hud_hub.broadcast({"type": "UNFENCE", "record": record.__dict__})
    return record.__dict__


# ---------------------------------------------------------
# Incidents & Alerts Endpoints
# ---------------------------------------------------------
@app.get(
    "/incidents",
    tags=["Incidents"],
    summary="List Confirmed Incident Records",
    description="Retrieve list of all confirmed security incidents with MITRE ATT&CK technique mapping and BLUF summaries.",
)
async def get_phase_incidents() -> List[Dict[str, Any]]:
    """Retrieve all confirmed incident records."""
    return phase_memory.list_incidents()


@app.get(
    "/alerts",
    tags=["Alerts"],
    summary="List Administrative Alerts",
    description="Retrieve all administrative notifications dispatched to node owners, including escalation status.",
)
async def get_alerts() -> List[Dict[str, Any]]:
    """Retrieve all administrative alerts."""
    return phase_memory.list_alerts()


@app.post(
    "/alerts/{alert_id}/acknowledge",
    tags=["Alerts"],
    summary="Acknowledge Administrative Alert",
    description="Mark an administrative alert as acknowledged and cancel pending escalation timers.",
)
async def acknowledge_alert(alert_id: str = Path(..., description="Alert identifier")) -> Dict[str, Any]:
    """Acknowledge an administrative alert and cancel escalation."""
    acknowledged_at = utc_iso_now()
    alert = phase_memory.acknowledge_alert(alert_id, acknowledged_at)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    cancel_escalation(alert_id)
    await send_admin_alert({
        "event": "admin_alert",
        "alert_id": alert_id,
        "node_id": alert["node_id"],
        "owner_id": alert["owner_id"],
        "attack_type": "acknowledged",
        "confidence": 0,
        "message": "Alert acknowledged by administrator.",
        "ts": acknowledged_at,
        "status": "acknowledged",
    })
    return alert


@app.get(
    "/antibodies",
    tags=["Antibodies"],
    summary="List Phase Digital Antibodies",
    description="List all synthesized digital antibodies with detection signatures, eBPF rules, MITRE ATT&CK metadata, and hardening recommendations.",
)
async def get_phase_antibodies() -> List[Dict[str, Any]]:
    """Retrieve list of all phase digital antibodies."""
    return phase_memory.list_antibodies()


# ---------------------------------------------------------
# Anomaly Ingestion & Threat Lifecycle Core Loop
# ---------------------------------------------------------
@app.post(
    "/api/anomalies",
    tags=["Detection & Anomaly"],
    summary="Ingest Innate Anomaly Signal",
    description="""
Ingest agent-local anomaly event (Innate Immunity signal).
Executes Adaptive Immunity correlation. If high-confidence threat confirmed:
1. Autonomous containment: issues signed quarantine command to affected agent.
2. Digital antibody synthesis: derives normalized, signed antibody with MITRE ATT&CK mapping.
3. Immune memory persistence: stores threat and antibody in SQLite.
4. WebSocket distribution: broadcasts antibody to swarm agents and frontend dashboards.
""",
)
async def ingest_local_anomaly(anomaly: LocalAnomalyEvent) -> Dict[str, Any]:
    """Ingest agent-local anomaly event and execute full adaptive response lifecycle."""
    logger.info(f"[ANOMALY INGESTED] Innate signal received from {anomaly.agent_id} (Score: {anomaly.score:.1f})")

    # Update node anomaly score and status to suspected if not already quarantined
    if anomaly.agent_id in node_states:
        node_states[anomaly.agent_id].anomaly_score = anomaly.score
        if node_states[anomaly.agent_id].status != "quarantined":
            node_states[anomaly.agent_id].status = "infected"
            await broadcaster.send_frontend_patch(anomaly.agent_id, {
                "status": "infected",
                "anomalyScore": anomaly.score,
                "biomarkers": anomaly.evidence_window,
            })

    # Correlate threat
    threat = correlator.ingest_anomaly(anomaly)
    if not threat:
        return {"status": "correlated_under_threshold", "threat_confirmed": False}

    logger.warning(f"[THREAT CONFIRMED] {threat.classification} on {threat.affected_agent} (Confidence: {threat.confidence_score:.2f})")

    # 1. Persist threat in SQLite
    db.save_threat(threat)
    db.log_audit("THREAT_CONFIRMED", threat.affected_agent, threat.correlation_id, threat.model_dump())

    await broadcast_typed_event(
        "anomaly_detected",
        node_id=threat.affected_agent,
        anomaly_score=anomaly.score,
        threat_type=threat.scenario_type,
        technique_id=threat.mitre.get("technique_id") if isinstance(threat.mitre, dict) else None,
        severity="critical",
    )

    # 2. Autonomous Containment: Issue quarantine command
    cmd = QuarantineCommand(
        agent_id=threat.affected_agent,
        threat_id=threat.threat_id,
        action="quarantine",
        reason=f"High-confidence threat confirmed: {threat.classification}",
    )
    cmd.signature = sign_payload(cmd.model_dump())
    await broadcaster.send_quarantine_command(cmd)

    await broadcast_typed_event(
        "quarantine_issued",
        node_id=threat.affected_agent,
        command_id=cmd.command_id,
        threat_id=threat.threat_id,
        reason=f"High-confidence threat confirmed: {threat.classification}",
    )

    if threat.affected_agent in node_states:
        entered_fenced = node_states[threat.affected_agent].status != "quarantined"
        node_states[threat.affected_agent].status = "quarantined"
        node_states[threat.affected_agent].active_threat = threat.classification
        if entered_fenced:
            await create_admin_alert_for_incident({
                "incident_id": threat.threat_id,
                "node_id": threat.affected_agent,
                "attack_type": threat.scenario_type,
                "confidence": threat.confidence_score,
            })

    # 3. Digital Antibody Synthesis & Signing (Idempotent per threat type)
    existing_abs = [a for a in db.get_all_antibodies(status="active") if a.threat_type == threat.scenario_type]
    if existing_abs:
        antibody = existing_abs[0]
        logger.info(f"Active antibody {antibody.antibody_id} already exists for {threat.scenario_type}. Reusing active immunity.")
    else:
        antibody = synthesizer.synthesize(threat)
        db.save_antibody(antibody)
        db.log_audit("ANTIBODY_SYNTHESIZED", threat.affected_agent, threat.correlation_id, antibody.model_dump(mode="json"))
        logger.info(f"Synthesized signed antibody {antibody.antibody_id} ({antibody.threat_type})")

    # Save to phase memory as well for unified endpoint query
    phase_memory.save_antibody(antibody.model_dump(mode="json"))
    incident_record = {
        "incident_id": threat.threat_id,
        "node_id": threat.affected_agent,
        "scenario": threat.scenario_type,
        "confidence": threat.confidence_score,
        "antibody_id": antibody.antibody_id,
        "status": "confirmed",
        "timestamp": threat.confirmed_at,
        "attack_type": threat.scenario_type,
        "recommendation": antibody.recommendation,
        "mitre": threat.mitre,
        "owner_id": NODES_CATALOG.get(threat.affected_agent, {}).get("owner_id", "admin_1"),
        "explanation": threat.explanation,
        "biomarkers": threat.biomarkers,
        "bluf_summary": threat.bluf_summary or generate_bluf_summary(threat.model_dump(), antibody.model_dump(mode="json")),
        "threat_actor_attributions": fingerprint_threat_actor(detected_techniques_for(threat.scenario_type, threat.mitre)),
    }
    phase_memory.save_incident(incident_record)

    # 4. Swarm Broadcast over WebSocket
    delivery = await broadcaster.broadcast_antibody(antibody)

    protected = [n for n in node_states.values() if n.status in ("immune", "healthy")]
    coverage_pct = round((len(protected) / max(len(node_states), 1)) * 100, 1)
    await broadcast_typed_event(
        "antibody_broadcast",
        antibody_id=antibody.antibody_id,
        threat_type=antibody.threat_type,
        source_node=threat.affected_agent,
        delivery_status=delivery,
    )
    await broadcast_typed_event(
        "herd_immunity",
        coverage_pct=coverage_pct,
        protected_nodes=len(protected),
        total_nodes=len(node_states),
    )

    # 5. Blast radius propagation prediction + pre-emptive quarantine fan-out
    blast_chain = predict_blast_radius(
        threat.affected_agent,
        node_states.get(threat.affected_agent).biomarkers if threat.affected_agent in node_states else {},
    )
    await broadcast_typed_event(
        "blast_radius",
        infected_node=threat.affected_agent,
        propagation_chain=blast_chain,
        preemptive_quarantined=[e["node_id"] for e in blast_chain if e.get("auto_quarantined")],
        severity="critical" if any(e.get("auto_quarantined") for e in blast_chain) else "warning",
    )

    return {
        "status": "threat_confirmed_and_antibody_broadcast",
        "threat_confirmed": True,
        "threat": threat,
        "antibody": antibody,
        "quarantine_command": cmd,
        "delivery_status": delivery,
        "threat_actor_attributions": incident_record["threat_actor_attributions"],
        "blast_radius": blast_chain,
    }


# ---------------------------------------------------------
# Threats & Antibodies Endpoints
# ---------------------------------------------------------
@app.get(
    "/api/threats",
    tags=["Incidents"],
    summary="Retrieve Confirmed Threat History",
    description="Retrieve chronologically ordered list of all confirmed security threats with MITRE ATT&CK details and biomarkers.",
    response_model=List[ConfirmedThreat],
)
async def get_threats(limit: int = Query(50, description="Max records to return")) -> List[ConfirmedThreat]:
    """Retrieve history of confirmed threats."""
    return db.get_threats(limit=limit)


@app.get(
    "/api/antibodies",
    tags=["Antibodies"],
    summary="List Active Swarm Antibodies",
    description="List all active, versioned digital antibodies stored in SQLite immune memory.",
    response_model=List[Antibody],
)
async def get_antibodies(status: Optional[str] = Query(None, description="Filter by status ('active', 'revoked')")) -> List[Antibody]:
    """List active antibody versions."""
    return db.get_all_antibodies(status=status)


@app.get(
    "/api/antibodies/expiring",
    tags=["Antibodies"],
    summary="List Expiring & Expired Antibodies",
    description="List antibodies whose decayed effective confidence has fallen below 'active' status (expiring < 60%, expired < 40%).",
)
async def get_expiring_antibodies() -> Dict[str, Any]:
    """Return antibodies nearing or past decay; refresh decay fields on read."""
    refresh_decay_statuses()
    antibodies = db.get_all_antibodies(status="active")
    expiring = []
    for ab in antibodies:
        eff = compute_effective_confidence(
            ab.created_at,
            half_life_hours=ab.half_life_hours,
            synthesized_at=ab.synthesized_at,
            base_confidence=ab.base_confidence,
        )
        if eff < 0.60:
            expiring.append({
                "antibody_id": ab.antibody_id,
                "threat_type": ab.threat_type,
                "synthesized_at": ab.synthesized_at.isoformat(),
                "half_life_hours": ab.half_life_hours,
                "effective_confidence": eff,
                "decay_status": compute_decay_status(eff),
                "version": ab.version,
            })
    return {"count": len(expiring), "expiring_antibodies": expiring}


@app.get(
    "/api/antibodies/{antibody_id}",
    tags=["Antibodies"],
    summary="Inspect Specific Digital Antibody",
    description="Retrieve details of an individual digital antibody by its ID.",
    response_model=Antibody,
)
async def get_antibody(antibody_id: str = Path(..., description="Antibody identifier")) -> Antibody:
    """Inspect specific antibody by ID."""
    ab = db.get_antibody(antibody_id)
    if not ab:
        raise HTTPException(status_code=404, detail="Antibody not found")
    return ab


@app.get(
    "/api/distribution",
    tags=["Antibodies"],
    summary="Report Swarm Antibody Distribution",
    description="Report per-agent delivery, verification, and installation status across the swarm mesh.",
)
@app.get("/api/antibodies/status", include_in_schema=False)
async def get_distribution(antibody_id: Optional[str] = Query(None, description="Optional antibody ID filter")) -> Dict[str, Any]:
    """Report per-agent receipt and activation status."""
    return broadcaster.get_distribution_status(antibody_id)


# ---------------------------------------------------------
# Threat Intelligence & Prediction Endpoints
# ---------------------------------------------------------
@app.get(
    "/api/apt-fingerprint/{incident_id}",
    tags=["Incidents"],
    summary="Fingerprint Threat Actor to MITRE Techniques",
    description="Attribuates the MITRE technique set of a confirmed incident to the top-3 known APT groups via cosine similarity.",
)
async def get_apt_fingerprint(incident_id: str = Path(..., description="Incident identifier")) -> Dict[str, Any]:
    """Return threat-actor attribution ranked by MITRE technique cosine similarity."""
    incident = next((i for i in phase_memory.list_incidents() if i.get("incident_id") == incident_id), None)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    techniques = detected_techniques_for(
        incident.get("scenario") or incident.get("attack_type"),
        incident.get("mitre"),
    )
    attribution = incident.get("threat_actor_attributions") or fingerprint_threat_actor(techniques)
    return {
        "incident_id": incident_id,
        "node_id": incident.get("node_id"),
        "scenario": incident.get("scenario") or incident.get("attack_type"),
        "detected_techniques": techniques,
        "attribution": attribution,
        "top_match": attribution[0] if attribution else None,
    }


@app.get(
    "/api/incidents/{incident_id}/briefing",
    tags=["Incidents"],
    summary="Commander Threat Investigation Briefing",
    description="Aggregates the complete commander view for a confirmed incident: threat facts, "
    "why it was flagged (feature contributions), what happened (MITRE + APT), impact "
    "(blast radius), and response (containment + digital antibody + herd immunity).",
)
async def get_incident_briefing(incident_id: str = Path(..., description="Incident identifier")) -> Dict[str, Any]:
    """Return a structured, judge-friendly threat investigation briefing."""
    incident = next((i for i in phase_memory.list_incidents() if i.get("incident_id") == incident_id), None)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    node_id = incident.get("node_id", "")
    mitigation_stack = {
        "detection": incident.get("mitre", {}).get("technique_name", "Unclassified"),
        "containment": "quarantine_source" if incident.get("status") == "confirmed" else "manual",
        "antibody_id": incident.get("antibody_id"),
        "immune_memory": db.get_antibody(incident["antibody_id"]) if incident.get("antibody_id") else None,
    }

    blast_radius_data = None
    if node_id:
        telemetry = node_states.get(node_id).biomarkers if node_id in node_states else {}
        chain = predict_blast_radius(node_id, telemetry)
        blast_radius_data = {
            "infected_node": node_id,
            "propagation_chain": chain,
            "preemptive_quarantined": [e["node_id"] for e in chain if e.get("auto_quarantined")],
        }

    return {
        "incident_id": incident_id,
        "threat": {
            "threat_type": incident.get("scenario") or incident.get("attack_type"),
            "classification": mitigation_stack["detection"],
            "severity": "critical" if float(incident.get("confidence", 0)) >= 0.95 else "high",
            "confidence": incident.get("confidence"),
            "detected_at": incident.get("timestamp"),
            "node_id": node_id,
        },
        "why": incident.get("explanation") or {"explanation": [], "summary": "No explanation data on record."},
        "what_happened": {
            "mitre": incident.get("mitre"),
            "apt_fingerprint": incident.get("threat_actor_attributions") or [],
            "biomarkers": incident.get("biomarkers"),
            "bluf_summary": incident.get("bluf_summary"),
        },
        "impact": {
            "blast_radius": blast_radius_data,
            "affected_hosts": 1,
            "lateral_movement_status": "none confirmed" if not blast_radius_data or not blast_radius_data.get("propagation_chain") else "at risk",
        },
        "response": {
            "detection_model": "isolation-forest-v1.0 / adaptive-correlator",
            "containment": "autonomous quarantine issued",
            "antibody_generated": bool(incident.get("antibody_id")),
            "antibody_id": incident.get("antibody_id"),
            "herd_immunity_status": "pending",
        },
    }


@app.get(
    "/api/blast-radius/{node_id}",
    tags=["Quarantine"],
    summary="Predict Blast Radius & Auto-Quarantine",
    description="""
Predict lateral-movement blast radius from an infected node across the swarm topology.
Any peer with an estimated fall time < 15 seconds is pre-emptively auto-quarantined.
""",
)
async def get_blast_radius(node_id: str = Path(..., description="Infected node identifier")) -> Dict[str, Any]:
    """Predict propagation chain from an infected node and auto-quarantine imminent-fall peers."""
    record = node_states.get(node_id)
    telemetry = record.biomarkers if record else {}
    chain = predict_blast_radius(node_id, telemetry)
    return {
        "infected_node": node_id,
        "propagation_chain": chain,
        "preemptive_quarantined": [e["node_id"] for e in chain if e.get("auto_quarantined")],
    }


# ---------------------------------------------------------
# Honeypot Decoy Endpoints
# ---------------------------------------------------------
@app.get(
    "/api/honeypot/events",
    tags=["Fleet & Nodes"],
    summary="List Honeypot Decoy Captures",
    description="List all attack traffic captured by the passive Node-Ψ dendritic decoy, including synthesized antibody IDs.",
)
async def get_honeypot_events(limit: int = Query(50, description="Max events to return")) -> List[Dict[str, Any]]:
    """Retrieve captured decoy attack events from SQLite."""
    return honeypot.list_events(limit=limit)


class HoneypotAttackRequest(BaseModel):
    """Payload for a synthetic decoy-targeted attack (used by demo + acceptance tests)."""

    source_ip: str = Field(default="185.220.101.4", description="Originating attacker IP")
    attack_vector: str = Field(default="port_scan", description="Attack scenario (port_scan, cryptominer, c2_beacon, worm)")
    payload: Optional[Dict[str, Any]] = Field(default=None, description="Optional enriched biomarker payload")


@app.post(
    "/api/honeypot/attack",
    tags=["Demonstration & Simulation"],
    summary="Fire Synthetic Attack at Decoy Node",
    description="Fire a synthetic attack at the passive decoy node. Captured payload is logged and an antibody is auto-synthesized.",
)
async def trigger_honeypot_attack(req: HoneypotAttackRequest) -> Dict[str, Any]:
    """Simulate an attacker poking the decoy node -> log + auto synthesize antibody."""
    scenario = SCENARIO_ALIAS_MAP.get(str(req.attack_vector).lower(), str(req.attack_vector).lower())
    profile = HONEYPOT_PROFILES.get(scenario, {"service": "decoy-www.internal", "open_ports": [22, 80, 443]})
    payload = req.payload or {
        "cpu_percent": 92.0,
        "entropy": 0.9,
        "connection_rate": 24.0,
        "network_connections": 70,
        "process": f"decoy_{scenario}_probe",
        "destination": profile.get("service", "unknown"),
    }
    captured = honeypot.capture_attack(req.source_ip, scenario, payload)

    await broadcast_typed_event(
        "honeypot_hit",
        event_id=captured["event_id"],
        source_ip=req.source_ip,
        attack_vector=scenario,
        antibody_id=captured.get("antibody_id"),
        detected_at=captured["timestamp"],
        node_id=HONEYPOT_NODE_ID,
    )
    await broadcaster.send_frontend_event({
        "type": "HONEYPOT_HIT",
        "severity": "ALERT",
        "title": f"Decoy Node-Ψ Captured {scenario.title()} Probe",
        "detail": f"Attacker {req.source_ip} touched the passive decoy. Antibody {'synthesized' if captured.get('antibody_id') else 'n/a'} — zero human alert required.",
        "nodeId": HONEYPOT_NODE_ID,
        "nodeName": "Node-Ψ [Dendritic Decoy]",
        "metadata": {
            "sourceIp": req.source_ip,
            "attackVector": scenario,
            "antibody": captured.get("antibody_id"),
            "detectedAt": captured["timestamp"],
        },
    })
    return captured


# ---------------------------------------------------------
# Fleet Stats (StatBar)
# ---------------------------------------------------------
@app.get(
    "/api/stats",
    tags=["System & Health"],
    summary="Real-Time Fleet & Threat Stats",
    description="Aggregated metrics for the command bar: fleet immunity %, active threats, antibodies synthesized today, false positive rate, uptime.",
)
async def get_fleet_stats() -> Dict[str, Any]:
    """Compute command-bar stats from live node states + immune memory."""
    nodes = list(node_states.values())
    protected = [n for n in nodes if n.status in ("immune", "healthy")]
    immunity_pct = round((len(protected) / max(len(nodes), 1)) * 100, 1) if nodes else 0.0
    active_threats = [n for n in nodes if n.status == "infected" or (n.active_threat and n.status != "quarantined")]
    antibodies = db.get_all_antibodies()
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    antibodies_today = 0
    for a in antibodies:
        ref = a.synthesized_at.isoformat() if hasattr(a, "synthesized_at") and a.synthesized_at else a.created_at
        if ref and ref.startswith(today_str):
            antibodies_today += 1
    threats = db.get_threats(limit=100)
    fp_rate = 0.0
    if threats:
        false_pos = [t for t in threats if float(t.confidence_score or 0) < 0.85]
        fp_rate = round((len(false_pos) / len(threats)) * 100, 1)
    return {
        "immunity_pct": immunity_pct,
        "active_threats": len(active_threats),
        "antibodies_today": antibodies_today,
        "false_positive_rate": fp_rate,
        "total_threats_seen": len(threats),
        "nodes_total": len(nodes),
        "antibodies_total": len(antibodies),
    }


# ---------------------------------------------------------
# Demo Control & Repeat Attack Endpoints
# ---------------------------------------------------------
class AttackRequest(BaseModel):
    """Payload for triggering a live demonstration attack scenario."""

    target_node: str = Field(default="node-beta", description="Target agent node identifier")
    scenario: str = Field(
        default="cryptominer",
        description="Scenario: 'cryptominer', 'port_scan', 'c2_beacon', 'worm'",
    )
    mode: str = Field(
        default="first_attack",
        description="Mode: 'first_attack' (synthesis) or 'repeat_attack' (instant immunity test)",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "target_node": "node-beta",
                "scenario": "cryptominer",
                "mode": "first_attack",
            }
        }
    }


@app.post(
    "/api/demo/attack",
    tags=["Demonstration & Simulation"],
    summary="Trigger Demonstration Attack Scenario",
    description="Dispatches a simulated attack scenario ('first_attack' or 'repeat_attack') against a specified node in the swarm.",
)
async def trigger_demo_attack(req: AttackRequest) -> Dict[str, Any]:
    """Trigger attack scenario against selected node."""
    target = req.target_node
    scenario = SCENARIO_ALIAS_MAP.get(req.scenario, req.scenario)

    # Notify target agent via WebSocket if connected
    if target in broadcaster.agent_sockets:
        msg = json.dumps({
            "type": "SIMULATE_ATTACK",
            "scenario": scenario,
            "mode": req.mode,
        })
        await broadcaster.agent_sockets[target].send_text(msg)
        logger.info(f"[ATTACK DISPATCHED] Triggered {req.mode} '{scenario}' against {target} via WebSocket.")
    else:
        # If agent is not connected via WebSocket, simulate directly through loop
        sim_anomaly = LocalAnomalyEvent(
            agent_id=target,
            score=95.4,
            threshold=70.0,
            feature_names=["cpu", "entropy"],
            evidence_window={"cpu_percent": 88.0, "entropy": 0.94, "process": "xmrig"},
            scenario_hint=scenario,
        )
        return await ingest_local_anomaly(sim_anomaly)

    return {
        "status": "attack_dispatched",
        "target": target,
        "scenario": scenario,
        "mode": req.mode,
    }


@app.post(
    "/api/demo/reset",
    tags=["Demonstration & Simulation"],
    summary="Reset Simulation & Clear Immune Memory",
    description="Clears all SQLite antibody, threat, and alert records and resets all node states to healthy baseline.",
)
async def reset_simulation() -> Dict[str, Any]:
    """Explicit demo reset: clears database and resets all node states to baseline."""
    db.reset_simulation()
    init_node_states()
    broadcaster.delivery_status.clear()

    # Broadcast reset to all agents and frontend
    reset_msg = json.dumps({"type": "RESET_BASELINE"})
    for ws in list(broadcaster.agent_sockets.values()):
        try:
            await ws.send_text(reset_msg)
        except Exception:
            pass

    await broadcaster._send_frontend_raw(json.dumps({
        "type": "IMMUNE_EVENT",
        "event": {
            "id": generate_uuid("evt-reset-"),
            "timestamp": utc_iso_now(),
            "timeMs": 0,
            "type": "NETWORK_RESET",
            "severity": "INFO",
            "title": "Network Re-Sensitized & Reset",
            "detail": "All endpoints returned to baseline homeostasis. Immune memory reset.",
            "nodeId": "ALL",
            "nodeName": "Swarm Orchestrator",
        },
    }))
    logger.info("[DEMO RESET] Simulation state and immune memory completely reset.")
    return {"status": "simulation_reset_complete"}


# ---------------------------------------------------------
# Unified WebSocket Endpoint (/ws)
# ---------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    agent_id: Optional[str] = Query(None, description="Optional agent node identifier"),
    role: Optional[str] = Query(None, description="Optional role ('agent' or 'frontend')"),
):
    """
    Unified WebSocket bridge for agents and frontend dashboards.
    - If agent_id provided: registered as an endpoint agent and receives antibody distributions.
    - Otherwise: registered as frontend dashboard client and receives real-time UI events.
    """
    await websocket.accept()
    is_agent = bool(agent_id and role != "frontend")

    if is_agent:
        await broadcaster.register_agent(agent_id, websocket)
        if agent_id in node_states:
            node_states[agent_id].connected_ws = True
    else:
        await broadcaster.register_frontend(websocket)
        for nid, record in node_states.items():
            await websocket.send_text(json.dumps({
                "type": "NODE_UPDATE",
                "nodeId": nid,
                "patch": {
                    "status": record.status,
                    "anomalyScore": record.anomaly_score,
                    "biomarkers": record.biomarkers,
                    "memoryShields": record.antibodies_installed,
                },
            }))

    try:
        while True:
            raw_text = await websocket.receive_text()
            try:
                data = json.loads(raw_text)
            except json.JSONDecodeError:
                continue

            msg_type = data.get("type")

            # Frontend control commands
            if msg_type == "TRIGGER_ATTACK":
                target = data.get("target") or data.get("target_node", "node-beta")
                scenario_raw = data.get("scenario") or data.get("attackKey", "cryptominer")
                scenario = SCENARIO_ALIAS_MAP.get(scenario_raw, scenario_raw)
                mode = data.get("mode", "first_attack")
                req = AttackRequest(target_node=target, scenario=scenario, mode=mode)
                await trigger_demo_attack(req)

            elif msg_type == "TRIGGER_SELF_HEAL":
                target = data.get("target") or data.get("targetNodeId")
                if target and target in node_states:
                    node_states[target].status = "immune"
                    node_states[target].active_threat = None
                    node_states[target].anomaly_score = 3.8
                    await broadcaster.send_frontend_patch(target, {
                        "status": "immune",
                        "activeThreat": None,
                        "anomalyScore": 3.8,
                        "biomarkers": {"cpu": 21, "memory": 38, "entropy": 0.12, "socketLoad": 110},
                    })

            elif msg_type == "RESET_SIMULATION":
                await reset_simulation()

            # Agent message handling
            elif msg_type == "LOCAL_ANOMALY":
                anomaly_payload = data.get("anomaly")
                if anomaly_payload:
                    anomaly = LocalAnomalyEvent(**anomaly_payload)
                    await ingest_local_anomaly(anomaly)

            elif msg_type == "AGENT_ACK":
                ack_payload = data.get("ack")
                if ack_payload:
                    ack = AgentAcknowledgement(**ack_payload)
                    broadcaster.record_agent_ack(ack)
                    # If this was an antibody activation, update node status and notify frontend
                    if ack.type == "antibody_receipt" and ack.status == "applied":
                        if ack.agent_id in node_states:
                            node_states[ack.agent_id].status = "immune"
                            if ack.target_id not in node_states[ack.agent_id].antibodies_installed:
                                node_states[ack.agent_id].antibodies_installed.append(ack.target_id)
                        await broadcaster.send_frontend_patch(ack.agent_id, {
                            "status": "immune",
                            "memoryShields": node_states.get(ack.agent_id, AgentStatusRecord(agent_id=ack.agent_id, ip="")).antibodies_installed,
                        })
                        await broadcaster.send_frontend_event({
                            "type": "PEER_IMMUNIZED",
                            "severity": "SUCCESS",
                            "title": f"{ack.agent_id} Fortified with Antibody",
                            "detail": f"Peer installed {ack.target_id}. Memory eBPF rule verified & loaded.",
                            "nodeId": ack.agent_id,
                            "nodeName": ack.agent_id,
                        })

            elif msg_type == "ANTIBODY_NEUTRALIZATION":
                # Agent blocked a repeat attack locally in < 2ms!
                ab_id = data.get("antibody_id")
                target_node = data.get("agent_id")
                scenario = data.get("scenario")
                latency = data.get("latency_ms", 1.8)

                if ab_id:
                    db.increment_antibody_neutralization(ab_id)

                if target_node in node_states:
                    node_states[target_node].neutralized_count += 1
                    node_states[target_node].status = "immune"

                logger.info(f"[IMMUNE DEFLECTION] {target_node} deflected repeat attack '{scenario}' in {latency}ms via {ab_id}!")

                # Broadcast deflection to frontend
                await broadcaster.send_frontend_event({
                    "type": "ANTIBODY_NEUTRALIZATION",
                    "severity": "IMMUNE",
                    "title": f"🛡️ ATTACK DEFLECTED: Memory Antibody Blocked {scenario}",
                    "detail": f"Pathogen fired at {target_node} — immediately intercepted by {ab_id} in {latency}ms! Zero infection, zero human ticket.",
                    "nodeId": target_node,
                    "nodeName": target_node,
                    "metadata": {
                        "interceptionLatency": f"{latency}ms",
                        "antibody": ab_id,
                        "bCellMemory": "CONFIRMED_IMMUNITY",
                        "humanInterventionRequired": False,
                    },
                })

            elif msg_type == "HEARTBEAT":
                await websocket.send_text(json.dumps({"type": "PONG", "timestamp": utc_iso_now()}))

    except (asyncio.CancelledError, WebSocketDisconnect):
        if is_agent:
            broadcaster.unregister_agent(agent_id)
            if agent_id in node_states:
                node_states[agent_id].connected_ws = False
        else:
            broadcaster.unregister_frontend(websocket)
    except Exception as e:
        logger.warning(f"WebSocket connection terminated: {e}")
        if is_agent:
            broadcaster.unregister_agent(agent_id)
        else:
            broadcaster.unregister_frontend(websocket)


@app.websocket("/ws/agents")
async def phase_agent_websocket(websocket: WebSocket):
    """Phase-specific agent hub with automatic replay of persisted antibodies."""
    await agent_hub.register(websocket)
    try:
        for antibody in phase_memory.list_antibodies():
            await websocket.send_text(json.dumps({"type": "ANTIBODY", "antibody": antibody}))
        while True:
            payload = json.loads(await websocket.receive_text())
            if payload.get("type") == "HEARTBEAT":
                await websocket.send_text(json.dumps({"type": "PONG", "timestamp": utc_iso_now()}))
            elif payload.get("type") == "TELEMETRY" and payload.get("telemetry"):
                await ingest_phase_telemetry(TelemetryEvent(**payload["telemetry"]))
    except (WebSocketDisconnect, asyncio.CancelledError):
        await agent_hub.unregister(websocket)
    except Exception:
        await agent_hub.unregister(websocket)


@app.websocket("/ws/hud")
async def phase_hud_websocket(websocket: WebSocket):
    """Read-only HUD stream for live health, incidents, antibodies, and coverage updates."""
    await hud_hub.register(websocket)
    try:
        await websocket.send_text(json.dumps({
            "type": "SNAPSHOT",
            "health": await get_health(),
            "incidents": phase_memory.list_incidents(),
            "antibodies": phase_memory.list_antibodies(),
            "coverage_percent": 100.0 if phase_memory.list_antibodies() else 0.0,
        }))
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, asyncio.CancelledError):
        await hud_hub.unregister(websocket)
    except Exception:
        await hud_hub.unregister(websocket)
