"""
IMMUNE-NET Canonical Node Definitions
Defines the 8 participating agents in the cyber-immune swarm.
"""

from typing import Dict, Any, List

NODES_CATALOG: Dict[str, Dict[str, Any]] = {
    "node-alpha": {
        "id": "node-alpha",
        "name": "Node-α [Cortex Gateway]",
        "role": "API Ingress & Edge Proxy",
        "ip": "10.0.1.10",
        "wbcScouts": 12,
        "x": 18,
        "y": 28,
        "peers": ["node-beta", "node-theta", "node-eta"],
        "owner_id": "admin_1",
    },
    "node-beta": {
        "id": "node-beta",
        "name": "Node-β [Thymus Auth]",
        "role": "Identity & JWT Minting Cluster",
        "ip": "10.0.1.15",
        "wbcScouts": 16,
        "x": 42,
        "y": 18,
        "peers": ["node-alpha", "node-gamma", "node-theta"],
        "owner_id": "admin_2",
    },
    "node-gamma": {
        "id": "node-gamma",
        "name": "Node-γ [Medulla Vault]",
        "role": "Encrypted Ledger & Key Store",
        "ip": "10.0.1.20",
        "wbcScouts": 20,
        "x": 72,
        "y": 25,
        "peers": ["node-beta", "node-delta", "node-theta"],
        "owner_id": "admin_3",
    },
    "node-delta": {
        "id": "node-delta",
        "name": "Node-δ [Artery Pay]",
        "role": "Settlement & Payment Gateway",
        "ip": "10.0.1.25",
        "wbcScouts": 14,
        "x": 85,
        "y": 58,
        "peers": ["node-gamma", "node-epsilon"],
        "owner_id": "admin_4",
    },
    "node-epsilon": {
        "id": "node-epsilon",
        "name": "Node-ε [Myelin Worker]",
        "role": "Async Task & ML Pipeline",
        "ip": "10.0.1.30",
        "wbcScouts": 10,
        "x": 62,
        "y": 78,
        "peers": ["node-delta", "node-zeta", "node-theta"],
        "owner_id": "admin_5",
    },
    "node-zeta": {
        "id": "node-zeta",
        "name": "Node-ζ [Synapse DNS]",
        "role": "Service Discovery & Routing Mesh",
        "ip": "10.0.1.35",
        "wbcScouts": 12,
        "x": 35,
        "y": 72,
        "peers": ["node-epsilon", "node-eta", "node-theta"],
        "owner_id": "admin_6",
    },
    "node-eta": {
        "id": "node-eta",
        "name": "Node-η [Marrow Storage]",
        "role": "Blob Cluster & Immutable Snapshots",
        "ip": "10.0.1.40",
        "wbcScouts": 18,
        "x": 15,
        "y": 60,
        "peers": ["node-alpha", "node-zeta", "node-theta"],
        "owner_id": "admin_7",
    },
    "node-theta": {
        "id": "node-theta",
        "name": "Node-θ [Lymph Telemetry]",
        "role": "Swarm Orchestrator & Bio-Bus",
        "ip": "10.0.1.50",
        "wbcScouts": 22,
        "x": 48,
        "y": 45,
        "peers": ["node-alpha", "node-beta", "node-gamma", "node-epsilon", "node-zeta", "node-eta"],
        "owner_id": "admin_8",
    },
}

# Passive honeypot decoy (Dendritic Cell). NOT part of the active agent fleet —
# exists purely to attract and capture attack traffic for biomarker enrichment.
HONEYPOT_NODE_ID = "node-decoy"
HONEYPOT_NODE: Dict[str, Any] = {
    "id": HONEYPOT_NODE_ID,
    "name": "Node-Ψ [Dendritic Decoy]",
    "role": "Passive Honeypot Trap (Decoy)",
    "ip": "10.0.9.99",
    "wbcScouts": 0,
    "x": 50,
    "y": 88,
    "peers": [],
    "owner_id": "admin_1",
    "honeypot": True,
}

DEFAULT_NODE_IDS: List[str] = list(NODES_CATALOG.keys())

HONEYPOT_PROFILES: Dict[str, Dict[str, Any]] = {
    "cryptominer": {
        "service": "fake-mining-pool.api:3333",
        "open_ports": [3333, 8080, 443],
        "credential_payload": "root:miner_deploy_token",
    },
    "port_scan": {
        "service": "decoy-www.internal",
        "open_ports": [22, 80, 443, 3389, 8080],
        "credential_payload": "admin:decoy_creds",
    },
    "c2_beacon": {
        "service": "ghost-c2-relay.bio",
        "open_ports": [53, 443, 8443],
        "credential_payload": "callback:beacon_token",
    },
    "worm": {
        "service": "legacy-deploy-share",
        "open_ports": [445, 139, 22],
        "credential_payload": "svc_distro:worm_bait",
    },
}
