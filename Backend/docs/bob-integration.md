# IBM watsonx.x MCP Integration — IMMUNE-NET

This document describes how any MCP-capable agent (including IBM watsonx Bob) connects to the IMMUNE-NET orchestrator's Model Context Protocol tool server.

## 1. Server Info

| Field | Value |
| --- | --- |
| Name | `immune-net-bob-mcp` |
| Version | `1.0.0` |
| Protocol | JSON-RPC 2.0 over HTTP(S) |
| Endpoint | `POST http://localhost:8000/mcp` |
| Manifest | `GET http://localhost:8000/mcp` |

## 2. Tool List

| Tool | Description | Params |
| --- | --- | --- |
| `get_fleet_status` | Fleet immunity %, active threats, per-node summary | — |
| `get_node_detail` | Telemetry, anomaly score, antibody status, quarantine state | `node_id` |
| `quarantine_node` | Issue a signed QuarantineCommand; returns command_id | `node_id` |
| `release_node` | Reverse quarantine and restore swarm membership | `node_id` |
| `get_active_incidents` | Last-known BLUF briefings with APT attribution | — |
| `get_antibody_library` | All digital antibodies with decay status | — |
| `get_blast_radius` | Lateral-movement propagation risk chain | `node_id` |
| `run_simulation` | Trigger a 4-scenario attack simulation | `scenario` (`cryptominer`, `port_scan`, `c2_beacon`, `worm`) |

Run simulation is the only async tool: the server resolves the full attack lifecycle and returns the confirmed incident, generated antibody, and blast-radius containment in one response.

## 3. Example Calls

### 3.1 GET manifest

```powershell
Invoke-RestMethod -Uri "http://localhost:8000/mcp"
```

### 3.2 Fleet status (sync)

```
POST /mcp
Content-Type: application/json

{ "jsonrpc": "2.0", "id": 1, "method": "get_fleet_status", "params": {} }
```

### 3.3 Attack simulation (async)

```
POST /mcp
Content-Type: application/json

{ "jsonrpc": "2.0", "id": 2, "method": "run_simulation", "params": { "scenario": "port_scan" } }
```

Response payload:

```json
{
  "status": "threat_confirmed_and_antibody_broadcast",
  "threat_confirmed": true,
  "threat": { "threat_id": "...", "classification": "...", "confidence_score": 0.89, ... },
  "antibody": { "antibody_id": "AB-SYN-XDP-...", "signature": "...", ... },
  "quarantine_command": { "command_id": "qc-...", "action": "quarantine", ... },
  "delivery_status": { "delivered_count": 8, ... },
  "threat_actor_attributions": [ { "actor": "APT41", "confidence": 0.88 }, ... ],
  "blast_radius": { "propagation_chain": [ ... ], "preemptive_quarantined": [ ... ] }
}
```

## 4. HTTP Status & Errors

- `200` — successful JSON-RPC response (either `result` or `error`).
- `400` — malformed JSON-RPC envelope or unknown method.

Error frame:

```json
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32601, "message": "Method not found" } }
```

## 5. Frontend Console

The React HUD ships an interactive "Bob · IBM watsonx MCP Console" panel (`src/components/BobChat.jsx`) rendering quick tool chips, a params editor, and a JSON response viewport. All calls funnel through `callMCP(method, params)` in `src/hooks/useImmuneLive.js`.

## 6. Acceptance Proof

`python acceptance_test.py` benchmark step 8-D performs a live `get_fleet_status` MCP call and asserts a well-formed tool result — runnable end-to-end against a started orchestrator.