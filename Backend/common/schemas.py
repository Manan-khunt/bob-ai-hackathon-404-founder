"""
Data schemas and contracts for IMMUNE-NET.
Compliant with IBM BoB AI Innovation Hackathon PRD, OpenAPI 3.1 specifications, and Frontend integration.
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, model_validator
import uuid
from datetime import datetime, timezone


def utc_iso_now() -> str:
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def utc_now() -> datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def compute_effective_confidence(
    created_at: str,
    half_life_hours: float = 72.0,
    synthesized_at: Optional[datetime] = None,
    base_confidence: float = 1.0,
) -> float:
    """
    Exponential antibody decay model.

    Uses: base_confidence * (0.5 ** (age_hours / half_life_hours)).
    Age is measured from the latest (re-)synthesis timestamp.
    """
    ref = None
    if synthesized_at is not None:
        ref = synthesized_at
    elif created_at:
        try:
            ref = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            ref = None
    if ref is None:
        ref = utc_now()
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    age_hours = max(0.0, (utc_now() - ref).total_seconds() / 3600.0)
    try:
        return round(base_confidence * (0.5 ** (age_hours / max(half_life_hours, 0.001))), 4)
    except (TypeError, ValueError, ZeroDivisionError):
        return 0.0


def compute_decay_status(effective_confidence: Optional[float]) -> str:
    """Map effective confidence to a decay lifecycle status."""
    conf = effective_confidence if effective_confidence is not None else 1.0
    if conf < 0.40:
        return "expired"
    if conf < 0.60:
        return "expiring"
    return "active"


def generate_uuid(prefix: str = "") -> str:
    """Generate a UUID with optional prefix."""
    uid = str(uuid.uuid4())
    return f"{prefix}{uid}" if prefix else uid


# ---------------------------------------------------------
# Telemetry
# ---------------------------------------------------------
class TelemetryEvent(BaseModel):
    """Host-level behavioural biomarker telemetry emitted by swarm endpoint agents."""

    event_id: str = Field(
        default_factory=lambda: generate_uuid("evt-"),
        description="Unique identifier for telemetry event",
    )
    schema_version: int = Field(default=1, description="Telemetry schema version")
    timestamp: str = Field(
        default_factory=utc_iso_now,
        description="ISO 8601 UTC timestamp of telemetry capture",
    )
    agent_id: str = Field(
        ...,
        description="Originating swarm agent/node ID (e.g. 'node-alpha')",
    )
    process: str = Field(
        default="systemd",
        description="Active process name under inspection",
    )
    cpu_percent: float = Field(
        default=15.0,
        description="Process CPU utilization percentage (0.0 - 100.0)",
    )
    memory_percent: float = Field(
        default=30.0,
        description="Process memory utilization percentage (0.0 - 100.0)",
    )
    network_connections: int = Field(
        default=12,
        description="Count of active outbound network connections",
    )
    bytes_sent: int = Field(
        default=1024,
        description="Cumulative network egress bytes during window",
    )
    bytes_received: int = Field(
        default=2048,
        description="Cumulative network ingress bytes during window",
    )
    destination: str = Field(
        default="10.0.1.1:443",
        description="Primary remote destination socket (IP:Port)",
    )
    connection_rate: float = Field(
        default=2.0,
        description="Connection creation rate per second",
    )
    file_activity: int = Field(
        default=5,
        description="File open/write system call count per window",
    )
    scenario_id: Optional[str] = Field(
        default=None,
        description="Simulated attack scenario tag, if injected",
    )
    entropy: float = Field(
        default=0.12,
        description="Shannon entropy of payload/process space (0.0 - 1.0)",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "event_id": "evt-7f8a9b1c-3d2e-4f5a-8b9c-0d1e2f3a4b5c",
                "schema_version": 1,
                "timestamp": "2026-09-15T12:00:00.000000+00:00",
                "agent_id": "node-beta",
                "process": "xmrig",
                "cpu_percent": 94.5,
                "memory_percent": 42.0,
                "network_connections": 18,
                "bytes_sent": 8450,
                "bytes_received": 12400,
                "destination": "pool.minexmr.com:3333",
                "connection_rate": 8.5,
                "file_activity": 14,
                "scenario_id": "cryptominer",
                "entropy": 0.88,
            }
        }
    }


# ---------------------------------------------------------
# Innate Anomaly Detection Event (Agent -> Orchestrator)
# ---------------------------------------------------------
class LocalAnomalyEvent(BaseModel):
    """Innate immunity anomaly signal flagged locally by an agent's Isolation Forest."""

    event_id: str = Field(
        default_factory=lambda: generate_uuid("anom-"),
        description="Unique anomaly event ID",
    )
    schema_version: int = Field(default=1, description="Schema version")
    agent_id: str = Field(..., description="Reporting agent ID")
    timestamp: str = Field(
        default_factory=utc_iso_now,
        description="ISO 8601 UTC timestamp of anomaly detection",
    )
    model_version: str = Field(
        default="isolation-forest-v1",
        description="Local detection model identifier",
    )
    score: float = Field(
        ...,
        description="Calculated anomaly score / drift metric (0.0 - 100.0)",
    )
    threshold: float = Field(
        default=70.0,
        description="Detection threshold for triggering alert",
    )
    feature_names: List[str] = Field(
        default_factory=lambda: ["cpu_percent", "entropy"],
        description="Biomarker features that contributed to the anomaly",
    )
    evidence_window: Dict[str, Any] = Field(
        default_factory=dict,
        description="Captured biomarker metrics around the anomalous window",
    )
    correlation_id: str = Field(
        default_factory=lambda: generate_uuid("corr-"),
        description="Tracking correlation ID spanning threat lifecycle",
    )
    scenario_hint: Optional[str] = Field(
        default=None,
        description="Optional simulation hint for benchmarking",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "event_id": "anom-4b5c6d7e-8f9a-0b1c-2d3e-4f5a6b7c8d9e",
                "schema_version": 1,
                "agent_id": "node-beta",
                "timestamp": "2026-09-15T12:00:01.000000+00:00",
                "model_version": "isolation-forest-v1",
                "score": 95.4,
                "threshold": 70.0,
                "feature_names": ["cpu_percent", "entropy", "process"],
                "evidence_window": {
                    "cpu_percent": 95.0,
                    "entropy": 0.95,
                    "process": "xmrig",
                    "destination": "pool.supportxmr.com:443",
                },
                "correlation_id": "corr-11223344-5566-7788-9900-aabbccddeeff",
                "scenario_hint": "cryptominer",
            }
        }
    }


# ---------------------------------------------------------
# Confirmed Threat (Adaptive Immunity Correlation)
# ---------------------------------------------------------
class ConfirmedThreat(BaseModel):
    """High-confidence security threat confirmed through multi-node adaptive correlation."""

    threat_id: str = Field(
        default_factory=lambda: generate_uuid("threat-"),
        description="Unique threat identifier",
    )
    schema_version: int = Field(default=1, description="Schema version")
    classification: str = Field(
        ...,
        description="Human-readable threat classification name",
    )
    affected_agent: str = Field(..., description="ID of primary compromised node")
    peer_agents: List[str] = Field(
        default_factory=list,
        description="Cluster peer node IDs requiring immunisation",
    )
    confidence_score: float = Field(
        ...,
        description="Correlated confidence score (0.0 - 1.0)",
    )
    confidence_threshold: float = Field(
        default=0.85,
        description="Configured confidence threshold required for confirmation",
    )
    evidence_event_ids: List[str] = Field(
        default_factory=list,
        description="List of telemetry and anomaly event IDs providing evidence",
    )
    detection_model_or_rule_version: str = Field(
        default="adaptive-correlator-v1",
        description="Orchestrator detection engine version",
    )
    confirmed_at: str = Field(
        default_factory=utc_iso_now,
        description="ISO 8601 UTC timestamp when threat was confirmed",
    )
    recommended_neutralization_action: str = Field(
        default="quarantine_source",
        description="Recommended autonomous action",
    )
    correlation_id: str = Field(..., description="Tracking correlation ID")
    scenario_type: str = Field(
        ...,
        description="Canonical attack type ('cryptominer', 'port_scan', 'c2_beacon', 'worm')",
    )
    narrative: Optional[str] = Field(
        default=None,
        description="AI or rule-derived narrative explaining detection rationale",
    )
    biomarkers: Dict[str, Any] = Field(
        default_factory=dict,
        description="Key biomarker values at time of confirmation",
    )
    mitre: Dict[str, str] = Field(
        default_factory=lambda: {
            "technique_id": "UNKNOWN",
            "technique_name": "Unclassified",
            "tactic": "Unknown",
        },
        description="MITRE ATT&CK Enterprise Matrix mapping",
    )
    bluf_summary: Optional[str] = Field(
        default=None,
        description="Bottom Line Up Front executive summary",
    )
    explanation: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Feature contribution explanation data from the anomaly explainability engine",
    )

    @model_validator(mode="after")
    def populate_mitre_mapping(self):
        if not self.mitre or self.mitre.get("technique_id") in (None, "UNKNOWN", ""):
            from orchestrator.mitre_mapping import get_mitre_technique
            self.mitre = get_mitre_technique(self.scenario_type)
        return self

    model_config = {
        "json_schema_extra": {
            "example": {
                "threat_id": "threat-crypto-49a1b2c3",
                "schema_version": 1,
                "classification": "Autonomous Cryptominer / Ransomware Process",
                "affected_agent": "node-beta",
                "peer_agents": ["node-alpha", "node-gamma", "node-delta"],
                "confidence_score": 0.98,
                "confidence_threshold": 0.85,
                "evidence_event_ids": ["anom-4b5c6d7e", "evt-7f8a9b1c"],
                "detection_model_or_rule_version": "adaptive-correlator-crypto-v1",
                "confirmed_at": "2026-09-15T12:00:02.000000+00:00",
                "recommended_neutralization_action": "quarantine_source",
                "correlation_id": "corr-11223344-5566-7788-9900-aabbccddeeff",
                "scenario_type": "cryptominer",
                "narrative": "Sustained elevated CPU utilization (95.0%) and abnormal process entropy (0.95) correlated with unauthorized execution 'xmrig' on node-beta.",
                "biomarkers": {"cpu": 95.0, "entropy": 0.95, "process": "xmrig"},
                "mitre": {
                    "technique_id": "T1496",
                    "technique_name": "Resource Hijacking",
                    "tactic": "Impact",
                },
                "bluf_summary": "BOTTOM LINE: Node node-beta compromised by cryptominer — confirmed.\nConfidence: 98%. Action taken: quarantine_source.\n\nDETAILS:\n- Detection time: 2026-09-15T12:00:02.000000+00:00\n- MITRE ATT&CK: T1496 — Resource Hijacking (Impact)\n- Affected node owner: admin_1\n- Recommended hardening: Restrict outbound connections to known mining-pool IP ranges.\n- Network-wide immunity status: 8/8 nodes protected",
            }
        }
    }


# ---------------------------------------------------------
# Quarantine & Neutralization Command
# ---------------------------------------------------------
class QuarantineCommand(BaseModel):
    """Signed autonomous containment command sent to an endpoint agent."""

    command_id: str = Field(
        default_factory=lambda: generate_uuid("cmd-"),
        description="Unique command identifier",
    )
    schema_version: int = Field(default=1, description="Schema version")
    agent_id: str = Field(..., description="Target agent to quarantine or unfence")
    threat_id: str = Field(..., description="Associated confirmed threat ID")
    action: str = Field(
        default="quarantine",
        description="Action type: 'quarantine', 'release', 'drop_traffic', 'terminate_process'",
    )
    issued_at: str = Field(
        default_factory=utc_iso_now,
        description="ISO 8601 UTC timestamp of command issuance",
    )
    expires_at: Optional[str] = Field(
        default=None,
        description="Optional command expiration timestamp",
    )
    reason: str = Field(..., description="Justification for containment")
    signature: str = Field(
        default="",
        description="HMAC-SHA256 signature ensuring command authenticity",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "command_id": "cmd-8899aabb-ccdd-eeff-0011-223344556677",
                "schema_version": 1,
                "agent_id": "node-beta",
                "threat_id": "threat-crypto-49a1b2c3",
                "action": "quarantine",
                "issued_at": "2026-09-15T12:00:02.100000+00:00",
                "expires_at": None,
                "reason": "High-confidence threat confirmed: Autonomous Cryptominer / Ransomware Process",
                "signature": "3f4a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a",
            }
        }
    }


# ---------------------------------------------------------
# Digital Antibody
# ---------------------------------------------------------
class AntibodySignature(BaseModel):
    """Biomarker signature criteria for deterministic rule matching."""

    features: List[str] = Field(
        ...,
        description="Feature names evaluated by the antibody rule",
    )
    operator: str = Field(
        default="and",
        description="Logical operator combining threshold checks ('and', 'or')",
    )
    thresholds: Dict[str, Any] = Field(
        ...,
        description="Specific threshold boundaries triggering neutralization",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "features": ["cpu_percent", "entropy", "process_category"],
                "operator": "and",
                "thresholds": {"cpu_percent": 70.0, "entropy": 0.6, "process_category": "miner"},
            }
        }
    }


class Antibody(BaseModel):
    """Normalized, digitally signed Digital Antibody distributed across the swarm mesh."""

    antibody_id: str = Field(
        default_factory=lambda: generate_uuid("ab-"),
        description="Unique antibody identifier",
    )
    schema_version: int = Field(default=1, description="Antibody schema version")
    threat_type: str = Field(
        ...,
        description="Attack classification: 'cryptominer', 'port_scan', 'c2_beacon', 'worm'",
    )
    signature: AntibodySignature = Field(..., description="Biomarker detection signature")
    detection_rule: str = Field(
        ...,
        description="Human and agent readable rule specification",
    )
    neutralization_action: str = Field(
        ...,
        description="Instant neutralization action executed upon match (e.g. 'terminate_process_and_isolate')",
    )
    created_at: str = Field(
        default_factory=utc_iso_now,
        description="ISO 8601 UTC timestamp of synthesis",
    )
    source_threat_id: str = Field(
        ...,
        description="Confirmed threat ID that triggered synthesis",
    )
    model_version: str = Field(default="detector-v1", description="Synthesizer version")
    version: int = Field(default=1, description="Rule iteration number")
    issuer: str = Field(
        default="immune-net-orchestrator",
        description="Trusted orchestrator entity",
    )
    signature_algorithm: str = Field(
        default="hmac-sha256",
        description="Cryptographic algorithm for authenticity",
    )
    digital_signature: str = Field(
        default="",
        description="HMAC-SHA256 signature guaranteeing tamper-resistance",
    )
    status: str = Field(
        default="active",
        description="Status: 'active', 'revoked', 'superseded'",
    )
    neutralized_count: int = Field(
        default=0,
        description="Count of repeat attacks blocked by this antibody swarm-wide",
    )
    ebpf_rule: str = Field(
        default="",
        description="Synthesized eBPF / XDP bytecode rule definition",
    )
    recommendation: Optional[str] = Field(
        default=None,
        description="Hardening guidance for persistent immunity",
    )
    mitre: Dict[str, str] = Field(
        default_factory=lambda: {
            "technique_id": "UNKNOWN",
            "technique_name": "Unclassified",
            "tactic": "Unknown",
        },
        description="Standardized MITRE ATT&CK technique and tactic mapping",
    )
    synthesized_at: datetime = Field(
        default_factory=utc_now,
        description="ISO 8601 UTC timestamp of the most recent antibody synthesis / re-vaccination",
    )
    half_life_hours: float = Field(
        default=72.0,
        description="Exponential decay half-life in hours for effective antibody confidence",
    )
    base_confidence: float = Field(
        default=1.0,
        description="Effective confidence at synthesis time (decays exponentially thereafter)",
    )
    effective_confidence: Optional[float] = Field(
        default=None,
        description="Computed field: decayed confidence following 0.5^(age_hours / half_life_hours)",
    )
    decay_status: str = Field(
        default="active",
        description="Computed field: 'active', 'expiring', or 'expired' based on effective confidence",
    )

    @model_validator(mode="after")
    def populate_mitre_mapping(self):
        if not self.mitre or self.mitre.get("technique_id") in (None, "UNKNOWN", ""):
            from orchestrator.mitre_mapping import get_mitre_technique
            self.mitre = get_mitre_technique(self.threat_type)
        return self

    @model_validator(mode="after")
    def compute_decay_fields(self):
        self.effective_confidence = compute_effective_confidence(
            created_at=self.created_at,
            half_life_hours=self.half_life_hours,
            synthesized_at=self.synthesized_at,
            base_confidence=self.base_confidence,
        )
        self.decay_status = compute_decay_status(self.effective_confidence)
        return self

    model_config = {
        "json_schema_extra": {
            "example": {
                "antibody_id": "AB-CRYPTO-eBPF-49A1",
                "schema_version": 1,
                "threat_type": "cryptominer",
                "signature": {
                    "features": ["cpu_percent", "entropy", "process_category"],
                    "operator": "and",
                    "thresholds": {"cpu_percent": 70.0, "entropy": 0.6, "process_category": "miner"},
                },
                "detection_rule": "block if cpu_percent >= 70.0 and entropy >= 0.6 and process in ('xmrig', 'crypto_ransomware')",
                "neutralization_action": "terminate_process_and_isolate",
                "created_at": "2026-09-15T12:00:02.200000+00:00",
                "source_threat_id": "threat-crypto-49a1b2c3",
                "model_version": "detector-v1",
                "version": 1,
                "issuer": "immune-net-orchestrator",
                "signature_algorithm": "hmac-sha256",
                "digital_signature": "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e",
                "status": "active",
                "neutralized_count": 0,
                "ebpf_rule": 'SEC("tp/sched/fork") if p->entropy > 0.82 && disk_writes > 10MB/s => KILL_SIG9',
                "recommendation": "Restrict outbound connections to known mining-pool IP ranges. Enforce process allowlisting on this node type.",
                "mitre": {
                    "technique_id": "T1496",
                    "technique_name": "Resource Hijacking",
                    "tactic": "Impact",
                },
            }
        }
    }

    def to_frontend_dict(self) -> Dict[str, Any]:
        """Convert to the structure expected by the frontend React app."""
        frontend_attack_ids = {
            "cryptominer": "crypto_ransomware",
            "crypto_ransomware": "crypto_ransomware",
            "port_scan": "syn_cytokine_flood",
            "syn_cytokine_flood": "syn_cytokine_flood",
            "c2_beacon": "exfil_parasite",
            "exfil_parasite": "exfil_parasite",
            "worm": "kernel_blight",
            "kernel_blight": "kernel_blight",
        }
        frontend_antibody_ids = {
            "cryptominer": "AB-CRYPTO-eBPF-49A1",
            "crypto_ransomware": "AB-CRYPTO-eBPF-49A1",
            "port_scan": "AB-SYN-XDP-77B3",
            "syn_cytokine_flood": "AB-SYN-XDP-77B3",
            "c2_beacon": "AB-EXFIL-DNS-02C9",
            "exfil_parasite": "AB-EXFIL-DNS-02C9",
            "worm": "AB-KERNEL-LSM-19D4",
            "kernel_blight": "AB-KERNEL-LSM-19D4",
        }
        names = {
            "cryptominer": "CryptoLock-X (Ransomware Pathogen)",
            "crypto_ransomware": "CryptoLock-X (Ransomware Pathogen)",
            "port_scan": "SynFlood-Cytokine (DDoS Swarm)",
            "syn_cytokine_flood": "SynFlood-Cytokine (DDoS Swarm)",
            "c2_beacon": "ExfilParasite-Zero (Stealth Exfiltration)",
            "exfil_parasite": "ExfilParasite-Zero (Stealth Exfiltration)",
            "worm": "KernelBlight-9 (Privilege Escalation)",
            "kernel_blight": "KernelBlight-9 (Privilege Escalation)",
        }
        atk_id = frontend_attack_ids.get(self.threat_type, self.threat_type)
        ab_id = frontend_antibody_ids.get(self.threat_type, self.antibody_id)
        target_name = names.get(self.threat_type, self.threat_type)

        return {
            "id": ab_id,
            "name": f"Anti-{atk_id.replace('_', '-')}",
            "targetPathogen": target_name,
            "attackId": atk_id,
            "signatureHash": self.digital_signature[:10] if self.digital_signature else "0x4f8a129c",
            "eBpfRule": self.ebpf_rule or self.detection_rule,
            "synthesizedAt": self.created_at,
            "neutralizedCount": self.neutralized_count or 1,
            "recommendation": self.recommendation,
            "mitre": self.mitre,
            "halfLifeHours": self.half_life_hours,
            "effectiveConfidence": self.effective_confidence or 0.0,
            "decayStatus": self.decay_status,
        }


# ---------------------------------------------------------
# Acknowledgement & Agent Status
# ---------------------------------------------------------
class AgentAcknowledgement(BaseModel):
    """Acknowledgement message emitted by an agent upon receiving/installing an antibody or command."""

    ack_id: str = Field(
        default_factory=lambda: generate_uuid("ack-"),
        description="Unique acknowledgement ID",
    )
    agent_id: str = Field(..., description="Reporting agent ID")
    target_id: str = Field(..., description="Target antibody ID or command ID")
    type: str = Field(
        ...,
        description="Type: 'antibody_receipt', 'quarantine_applied', 'already_applied', 'rejected'",
    )
    status: str = Field(
        ...,
        description="Status: 'applied', 'active', 'rejected', 'failed'",
    )
    timestamp: str = Field(
        default_factory=utc_iso_now,
        description="ISO 8601 UTC timestamp of acknowledgement",
    )
    details: Optional[str] = Field(
        default=None,
        description="Diagnostic details or error text",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "ack_id": "ack-11223344-5566-7788-9900-aabbccddeeff",
                "agent_id": "node-delta",
                "target_id": "AB-CRYPTO-eBPF-49A1",
                "type": "antibody_receipt",
                "status": "applied",
                "timestamp": "2026-09-15T12:00:03.000000+00:00",
                "details": "Verified digital signature. Loaded eBPF filter into kernel LSM hook.",
            }
        }
    }


class AgentStatusRecord(BaseModel):
    """Real-time health and security posture record for a node in the swarm fleet."""

    agent_id: str = Field(..., description="Swarm node identifier")
    status: str = Field(
        default="healthy",
        description="Node security state: 'healthy', 'infected', 'quarantined', 'immune'",
    )
    ip: str = Field(default="10.0.1.10", description="Assigned mesh IP address")
    active_threat: Optional[str] = Field(
        default=None,
        description="Currently impacting threat classification, if any",
    )
    anomaly_score: float = Field(
        default=0.0,
        description="Latest Innate Isolation Forest anomaly score (0.0 - 100.0)",
    )
    antibodies_installed: List[str] = Field(
        default_factory=list,
        description="List of active antibody IDs protecting this host",
    )
    last_seen: str = Field(
        default_factory=utc_iso_now,
        description="ISO 8601 UTC timestamp of most recent heartbeat/telemetry",
    )
    connected_ws: bool = Field(
        default=False,
        description="Active WebSocket connection state",
    )
    neutralized_count: int = Field(
        default=0,
        description="Count of repeat attacks defended locally in sub-2ms",
    )
    biomarkers: Dict[str, Any] = Field(
        default_factory=dict,
        description="Live telemetry biomarker gauge values",
    )
    owner_id: Optional[str] = Field(
        default="admin_1",
        description="Designated administrative owner for escalation",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "agent_id": "node-alpha",
                "status": "immune",
                "ip": "10.0.1.10",
                "active_threat": None,
                "anomaly_score": 4.2,
                "antibodies_installed": ["AB-CRYPTO-eBPF-49A1"],
                "last_seen": "2026-09-15T12:00:05.000000+00:00",
                "connected_ws": True,
                "neutralized_count": 1,
                "biomarkers": {"cpu": 22.0, "memory": 40.0, "entropy": 0.12, "socketLoad": 105},
                "owner_id": "admin_1",
            }
        }
    }
