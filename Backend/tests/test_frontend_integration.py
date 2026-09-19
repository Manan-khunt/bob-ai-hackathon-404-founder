"""Tests for frontend-backend integration: endpoint shape validation."""

import asyncio
import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def app():
    from orchestrator.app import app as _app
    return _app


@pytest.fixture
def client(app):
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


def test_stats_returns_executive_metrics_shape(client):
    resp = asyncio.run(client.get("/api/stats"))
    assert resp.status_code == 200
    data = resp.json()
    for key in ("totalAlerts", "correlatedIncidents", "trueThreats", "falsePositives",
                "criticalIncidents", "activeSources", "falsePositiveReductionPct",
                "analystWorkloadReductionPct", "meanTimeToDetectSec", "meanTimeToTriageSec"):
        assert key in data, f"Missing key: {key}"
        assert isinstance(data[key], (int, float)), f"{key} not numeric"


def test_alerts_returns_array_with_correct_fields(client):
    resp = asyncio.run(client.get("/api/alerts"))
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0
    alert = data[0]
    for key in ("id", "incidentId", "source", "timestamp", "asset", "event",
                "normalizedEvent", "severity", "confidence", "correlationStatus",
                "classification", "mitre", "mitreName", "explanation"):
        assert key in alert, f"Missing alert key: {key}"


def test_alerts_alias_api_prefix(client):
    resp = asyncio.run(client.get("/api/alerts"))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_incidents_returns_prioritized_shape(client):
    resp = asyncio.run(client.get("/incidents"))
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) > 0
    inc = data[0]
    for key in ("id", "priorityRank", "priorityScore", "title", "classification",
                "severity", "confidence", "status", "mitreIds", "affectedAssets",
                "bluf", "timeline"):
        assert key in inc, f"Missing incident key: {key}"
    assert isinstance(inc["bluf"], dict)
    for bkey in ("bottomLine", "impact", "evidence", "mitreMapping", "recommendedAction"):
        assert bkey in inc["bluf"], f"Missing bluf key: {bkey}"
    assert isinstance(inc["timeline"], list)
    assert len(inc["timeline"]) > 0


def test_incidents_detail_by_id(client):
    resp = asyncio.run(client.get("/api/incidents/INC-1042"))
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "INC-1042"
    assert "bluf" in data
    assert "timeline" in data


def test_incidents_detail_not_found(client):
    resp = asyncio.run(client.get("/api/incidents/FAKE-ID"))
    assert resp.status_code == 404


def test_sources_returns_eight_sources(client):
    resp = asyncio.run(client.get("/api/sources"))
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 8
    src = data[0]
    for key in ("id", "name", "type", "eventsPerMin", "health", "status",
                "lastUpdate", "latencyMs", "coverage", "description"):
        assert key in src, f"Missing source key: {key}"


def test_bob_analyze_returns_response(client):
    resp = asyncio.run(client.post("/api/bob/analyze", json={"query": "What is the most important threat?"}))
    assert resp.status_code == 200
    data = resp.json()
    assert "response" in data
    assert isinstance(data["response"], str)
    assert len(data["response"]) > 50


def test_bob_analyze_bluf(client):
    resp = asyncio.run(client.post("/api/bob/analyze", json={"query": "Generate a BLUF briefing for INC-1042"}))
    assert resp.status_code == 200
    data = resp.json()
    assert "INC-1042" in data["response"]


def test_bob_analyze_default(client):
    resp = asyncio.run(client.post("/api/bob/analyze", json={"query": "Hello Bob"}))
    assert resp.status_code == 200
    data = resp.json()
    assert "response" in data


def test_health_endpoint(client):
    resp = asyncio.run(client.get("/health"))
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


def test_demo_threat_scenario(client):
    resp = asyncio.run(client.post("/api/demo/threat-scenario", json={"scenario": "coordinated_intrusion"}))
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("scenario") == "coordinated_intrusion"


def test_mcp_manifest(client):
    resp = asyncio.run(client.get("/mcp"))
    assert resp.status_code == 200
    data = resp.json()
    assert "tools" in data
    assert len(data["tools"]) > 0


def test_mcp_json_rpc(client):
    resp = asyncio.run(client.post("/mcp", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "get_fleet_status",
        "params": {},
    }))
    assert resp.status_code == 200
    data = resp.json()
    assert "jsonrpc" in data
    assert data.get("id") == 1
    assert "result" in data or "error" in data
