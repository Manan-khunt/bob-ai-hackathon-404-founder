"""
Bob MCP Server Endpoint for IMMUNE-NET.
Implements a Model Context Protocol-compatible JSON-RPC 2.0 over HTTP surface that
IBM BoB assistant can call via POST /mcp. Each exposed tool returns clean JSON.

Endpoints:
    GET  /mcp   -> tool manifest (MCP metadata)
    POST /mcp   -> JSON-RPC 2.0 dispatcher
"""

from typing import Any, Dict, List, Optional
import logging

from fastapi import APIRouter, Body
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from common.schemas import QuarantineCommand, generate_uuid
from common.crypto_utils import sign_payload
from orchestrator.apt_fingerprint import fingerprint_threat_actor, detected_techniques_for
from orchestrator.blast_radius import predict_blast_radius

logger = logging.getLogger("orchestrator.bob_mcp")

router = APIRouter()

MCP_SERVER_NAME = "immune-net-bob-mcp"
MCP_SERVER_VERSION = "1.1.0"

# Shared live context populated by orchestrator/app.py at startup.
MCP_CONTEXT: Dict[str, Any] = {}


def set_mcp_context(ctx: Dict[str, Any]) -> None:
    """Inject the live orchestrator context (node states, DB, memory, quarantine)."""
    MCP_CONTEXT.clear()
    MCP_CONTEXT.update(ctx)


class MCPRequest(BaseModel):
    """JSON-RPC 2.0 request envelope."""

    jsonrpc: str = Field(default="2.0")
    id: Any = Field(default=None)
    method: str = Field(...)
    params: Optional[Dict[str, Any]] = Field(default_factory=dict)


def _mcp_result(request_id: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _mcp_error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


# ---------------------------------------------------------------------------
# Tool implementations (each returns clean JSON)
# ---------------------------------------------------------------------------

def _tool_fleet_status(ctx: Dict[str, Any]) -> Dict[str, Any]:
    node_states = ctx["node_states"]
    nodes = list(node_states.values())
    if not nodes:
        return {"immunity_pct": 0, "active_threats": [], "node_summary": []}
    protected = [n for n in nodes if n.status in ("immune", "healthy")]
    immunity_pct = round((len(protected) / len(nodes)) * 100, 1)
    active_threats = [
        {"node_id": n.agent_id, "threat": n.active_threat}
        for n in nodes
        if n.active_threat
    ]
    node_summary = [
        {
            "node_id": n.agent_id,
            "status": n.status,
            "anomaly_score": n.anomaly_score,
            "antibodies_installed": n.antibodies_installed,
            "last_seen": n.last_seen,
        }
        for n in nodes
    ]
    return {"immunity_pct": immunity_pct, "active_threats": active_threats, "node_summary": node_summary}


def _tool_node_detail(ctx: Dict[str, Any], node_id: str) -> Dict[str, Any]:
    node_states = ctx["node_states"]
    record = node_states.get(node_id)
    if not record:
        return {"error": f"node {node_id} not found", "status": "unknown"}
    return {
        "node_id": record.agent_id,
        "telemetry": record.biomarkers,
        "anomaly_score": record.anomaly_score,
        "antibody_status": record.antibodies_installed,
        "quarantine_state": record.status,
        "active_threat": record.active_threat,
        "ip": record.ip,
        "last_seen": record.last_seen,
    }


def _tool_quarantine_node(ctx: Dict[str, Any], node_id: str) -> Dict[str, Any]:
    node_states = ctx["node_states"]
    quarantine_manager = ctx["quarantine_manager"]
    if node_id not in node_states:
        return {"error": f"node {node_id} not found", "command_id": None, "status": "not_found"}
    cmd = QuarantineCommand(
        agent_id=node_id,
        threat_id=generate_uuid("threat-mcp-"),
        action="quarantine",
        reason="Bob MCP tool invocation: quarantine_node",
    )
    cmd.signature = sign_payload(cmd.model_dump())
    quarantine_manager.fence(node_id, reason="Bob MCP tool invocation")
    node_states[node_id].status = "quarantined"
    return {"command_id": cmd.command_id, "status": "quarantine_issued", "agent_id": node_id}


def _tool_release_node(ctx: Dict[str, Any], node_id: str) -> Dict[str, Any]:
    node_states = ctx["node_states"]
    quarantine_manager = ctx["quarantine_manager"]
    if node_id not in node_states:
        return {"error": f"node {node_id} not found", "status": "not_found"}
    quarantine_manager.unfence(node_id, reason="Bob MCP tool invocation: release_node")
    if node_states[node_id].active_threat:
        node_states[node_id].status = "immune"
    else:
        node_states[node_id].status = "healthy"
    return {"status": "released", "agent_id": node_id}


def _tool_active_incidents(ctx: Dict[str, Any]) -> Dict[str, Any]:
    memory = ctx["phase_memory"]
    incidents = memory.list_incidents()
    briefings = []
    for inc in incidents:
        attribution = inc.get("threat_actor_attributions") or fingerprint_threat_actor(
            detected_techniques_for(inc.get("scenario") or inc.get("attack_type"), inc.get("mitre"))
        )
        briefings.append({
            "incident_id": inc.get("incident_id"),
            "timestamp": inc.get("timestamp") or inc.get("confirmed_at"),
            "node_id": inc.get("node_id"),
            "scenario": inc.get("scenario") or inc.get("attack_type"),
            "confidence": inc.get("confidence"),
            "bluf_summary": inc.get("bluf_summary"),
            "mitre": inc.get("mitre"),
            "threat_actor_attribution": attribution[0] if attribution else None,
            "top_apt_matches": attribution[:3],
        })
    return {"count": len(briefings), "incidents": briefings}


def _tool_antibody_library(ctx: Dict[str, Any]) -> Dict[str, Any]:
    db = ctx["db"]
    antibodies = db.get_all_antibodies()
    return {
        "count": len(antibodies),
        "antibodies": [
            {
                "antibody_id": ab.antibody_id,
                "threat_type": ab.threat_type,
                "created_at": ab.created_at,
                "synthesized_at": ab.synthesized_at.isoformat() if hasattr(ab, "synthesized_at") else ab.created_at,
                "half_life_hours": ab.half_life_hours,
                "effective_confidence": ab.effective_confidence,
                "decay_status": ab.decay_status,
                "status": ab.status,
                "version": ab.version,
                "neutralized_count": ab.neutralized_count,
                "mitre": ab.mitre,
            }
            for ab in antibodies
        ],
    }


def _tool_threat_feed(ctx: Dict[str, Any]) -> Dict[str, Any]:
    pipeline = ctx.get("threat_pipeline")
    db = ctx["db"]
    if pipeline:
        events = pipeline.get_threat_feed(limit=50)
    else:
        events = db.get_normalized_events(limit=50)
    return {"count": len(events), "events": events, "demo_note": "May include synthetic hackathon demo feeds."}


def _tool_prioritized_incidents(ctx: Dict[str, Any]) -> Dict[str, Any]:
    pipeline = ctx.get("threat_pipeline")
    db = ctx["db"]
    if pipeline:
        incidents = pipeline.list_prioritized_incidents(limit=20)
    else:
        incidents = db.get_pipeline_incidents(limit=20)
    brief = [
        {
            "incident_id": inc.get("incident_id"),
            "priority_score": inc.get("priority_score"),
            "classification": inc.get("classification"),
            "confidence": inc.get("confidence_score"),
            "mitre": inc.get("mitre"),
            "bluf": inc.get("bluf"),
        }
        for inc in incidents
    ]
    return {"count": len(brief), "incidents": brief}


def _tool_false_positives(ctx: Dict[str, Any]) -> Dict[str, Any]:
    pipeline = ctx.get("threat_pipeline")
    if pipeline:
        fps = pipeline.list_false_positives(limit=20)
    else:
        fps = [
            i for i in ctx["db"].get_pipeline_incidents(limit=100)
            if i.get("classification") == "FALSE_POSITIVE"
        ]
    return {"count": len(fps), "false_positives": fps}


def _tool_incident_summary(ctx: Dict[str, Any], incident_id: str) -> Dict[str, Any]:
    pipeline = ctx.get("threat_pipeline")
    if pipeline:
        summary = pipeline.get_incident_summary(incident_id)
    else:
        summary = ctx["db"].get_pipeline_incident(incident_id)
    if not summary:
        return {"error": f"incident {incident_id} not found"}
    return summary


def _tool_commander_bluf(ctx: Dict[str, Any], incident_id: str) -> Dict[str, Any]:
    summary = _tool_incident_summary(ctx, incident_id)
    if summary.get("error"):
        return summary
    bluf = summary.get("bluf") or {}
    return {
        "incident_id": incident_id,
        "classification": summary.get("classification"),
        "priority": {
            "score": summary.get("priority_score"),
            "level": summary.get("priority_level"),
        },
        "bluf": bluf,
    }


def _tool_explain_correlation(ctx: Dict[str, Any], incident_id: str) -> Dict[str, Any]:
    pipeline = ctx.get("threat_pipeline")
    if pipeline:
        explanation = pipeline.explain_correlation(incident_id)
    else:
        inc = ctx["db"].get_pipeline_incident(incident_id)
        explanation = {
            "incident_id": incident_id,
            "correlation_score": inc.get("correlation_score") if inc else None,
            "audit": inc.get("audit") if inc else None,
        } if inc else None
    if not explanation:
        return {"error": f"incident {incident_id} not found"}
    return explanation


def _tool_blast_radius(ctx: Dict[str, Any], node_id: str) -> Dict[str, Any]:
    node_states = ctx["node_states"]
    telemetry = {}
    if node_id in node_states:
        telemetry = node_states[node_id].biomarkers or {}
    chain = predict_blast_radius(node_id, telemetry)
    return {
        "infected_node": node_id,
        "propagation_chain": chain,
        "preemptive_quarantined": [
            entry["node_id"] for entry in chain if entry.get("auto_quarantined")
        ],
    }


TOOL_REGISTRY: Dict[str, Dict[str, Any]] = {
    "get_fleet_status": {
        "description": "Fleet immunity percentage, active threats, and per-node summary.",
        "handler": _tool_fleet_status,
    },
    "get_node_detail": {
        "description": "Telemetry, anomaly score, antibody status, and quarantine state for a node.",
        "handler": _tool_node_detail,
    },
    "quarantine_node": {
        "description": "Issue a signed QuarantineCommand for a node. Returns command_id + status.",
        "handler": _tool_quarantine_node,
    },
    "release_node": {
        "description": "Reverse quarantine for a node and restore swarm membership.",
        "handler": _tool_release_node,
    },
    "get_active_incidents": {
        "description": "Last-known BLUF incident briefings with APT threat-actor attribution.",
        "handler": _tool_active_incidents,
    },
    "get_antibody_library": {
        "description": "All digital antibodies from SQLite immune memory with decay status.",
        "handler": _tool_antibody_library,
    },
    "get_blast_radius": {
        "description": "Lateral-movement propagation risk chain from an infected node.",
        "handler": _tool_blast_radius,
    },
    "get_threat_feed": {
        "description": "Recent normalized multi-source threat events from the ingestion pipeline.",
        "handler": _tool_threat_feed,
    },
    "get_prioritized_incidents": {
        "description": "Pipeline incidents sorted by priority with MITRE and BLUF summaries.",
        "handler": _tool_prioritized_incidents,
    },
    "get_false_positives": {
        "description": "Incidents classified as FALSE_POSITIVE by deterministic triage.",
        "handler": _tool_false_positives,
    },
    "get_incident_summary": {
        "description": "Full pipeline incident record including audit trail.",
        "handler": _tool_incident_summary,
    },
    "generate_commander_bluf": {
        "description": "Commander-oriented BLUF block for a pipeline incident.",
        "handler": _tool_commander_bluf,
    },
    "explain_correlation": {
        "description": "Explain why events were correlated into an incident.",
        "handler": _tool_explain_correlation,
    },
}

# Async tools resolved by the application layer (they need awaiting):
ASYNC_TOOLS = {"run_simulation"}


def dispatch(method: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """Synchronously dispatch a JSON-RPC method call to a registered MCP tool."""
    return dispatch_with_context(MCP_CONTEXT, method, params)


def dispatch_with_context(ctx: Dict[str, Any], method: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """Dispatch a non-async method using an explicit live context."""
    params = params or {}
    tool = TOOL_REGISTRY.get(method)
    if not tool:
        raise KeyError(method)
    handler = tool["handler"]
    if method in ("get_node_detail", "quarantine_node", "release_node", "get_blast_radius"):
        return handler(ctx, params.get("node_id") or "")
    if method in ("get_incident_summary", "generate_commander_bluf", "explain_correlation"):
        return handler(ctx, params.get("incident_id") or "")
    return handler(ctx)


def build_manifest() -> Dict[str, Any]:
    """Return the MCP server + tool manifest for GET /mcp."""
    return {
        "server": MCP_SERVER_NAME,
        "version": MCP_SERVER_VERSION,
        "protocol": "json-rpc-2.0",
        "transport": "http",
        "endpoint": "http://localhost:8000/mcp",
        "tools": [
            {
                "name": name,
                "description": spec["description"],
                "parameters": _parameters_for(name),
            }
            for name, spec in TOOL_REGISTRY.items()
        ]
        + [
            {
                "name": "run_simulation",
                "description": "Trigger one of 4 attack scenarios (cryptominer, port_scan, c2_beacon, worm). Returns incident_id.",
                "parameters": [{"name": "scenario", "type": "string", "required": True, "example": "cryptominer"}],
            }
        ],
        "integration": "IBM BoB AI Innovation Hackathon (IMMUNE-NET)",
    }


def _parameters_for(name: str) -> List[Dict[str, Any]]:
    if name in ("get_node_detail", "quarantine_node", "release_node", "get_blast_radius"):
        return [{"name": "node_id", "type": "string", "required": True, "example": "node-beta"}]
    if name in ("get_incident_summary", "generate_commander_bluf", "explain_correlation"):
        return [{"name": "incident_id", "type": "string", "required": True, "example": "inc-00000000-0000-0000-0000-000000000001"}]
    if name == "run_simulation":
        return [{"name": "scenario", "type": "string", "required": True, "example": "cryptominer"}]
    return []


@router.get("/mcp")
async def mcp_manifest() -> Dict[str, Any]:
    """GET handler serving the MCP tool manifest."""
    return build_manifest()


@router.post("/mcp")
async def mcp_json_rpc(request: MCPRequest = Body(...)) -> Dict[str, Any]:
    """POST handler implementing JSON-RPC 2.0 dispatch over HTTP."""
    method = request.method

    if method == "run_simulation":
        run_scenario = MCP_CONTEXT.get("run_scenario_async")
        if not run_scenario:
            return _mcp_error(request.id, -32602, "run_simulation unavailable: orchestrator not initialized")
        try:
            result = await run_scenario((request.params or {}).get("scenario") or "cryptominer")
            return _mcp_result(request.id, jsonable_encoder(result))
        except Exception as exc:
            return _mcp_error(request.id, -32603, f"run_simulation failed: {exc}")

    if method not in TOOL_REGISTRY:
        return _mcp_error(request.id, -32601, f"Method not found: {method}")

    try:
        result = dispatch_with_context(MCP_CONTEXT, method, request.params)
        return _mcp_result(request.id, jsonable_encoder(result))
    except KeyError:
        return _mcp_error(request.id, -32601, f"Method not found: {method}")
    except Exception as exc:
        logger.error(f"MCP tool '{method}' failed: {exc}")
        return _mcp_error(request.id, -32603, f"Internal error in {method}: {exc}")