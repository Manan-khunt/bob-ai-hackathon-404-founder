"""
Digital Antibody Synthesizer Engine for IMMUNE-NET.
Generates normalized, versioned, and cryptographically signed Digital Antibodies from confirmed threats,
binding detection signatures, eBPF rules, MITRE ATT&CK intelligence, and remediation recommendations.
"""

from typing import Dict, Any
from common.schemas import (
    ConfirmedThreat,
    Antibody,
    AntibodySignature,
    generate_uuid,
    utc_iso_now,
)
from common.crypto_utils import sign_payload, compute_hash
from orchestrator.recommend import get_recommendation
from orchestrator.mitre_mapping import get_mitre_technique

# Pre-defined normalized profiles matching PRD and frontend
ANTIBODY_PROFILES: Dict[str, Dict[str, Any]] = {
    "cryptominer": {
        "id_prefix": "AB-CRYPTO-eBPF-",
        "features": ["cpu_percent", "entropy", "process_category"],
        "operator": "and",
        "thresholds": {"cpu_percent": 70.0, "entropy": 0.6, "process_category": "miner"},
        "detection_rule": "block if cpu_percent >= 70.0 and entropy >= 0.6 and process in ('xmrig', 'crypto_ransomware')",
        "neutralization_action": "terminate_process_and_isolate",
        "ebpf_rule": 'SEC("tp/sched/fork") if p->entropy > 0.82 && disk_writes > 10MB/s => KILL_SIG9',
    },
    "crypto_ransomware": {
        "id_prefix": "AB-CRYPTO-eBPF-",
        "features": ["cpu_percent", "entropy", "process_category"],
        "operator": "and",
        "thresholds": {"cpu_percent": 70.0, "entropy": 0.6, "process_category": "miner"},
        "detection_rule": "block if cpu_percent >= 70.0 and entropy >= 0.6 and process in ('xmrig', 'crypto_ransomware')",
        "neutralization_action": "terminate_process_and_isolate",
        "ebpf_rule": 'SEC("tp/sched/fork") if p->entropy > 0.82 && disk_writes > 10MB/s => KILL_SIG9',
    },
    "port_scan": {
        "id_prefix": "AB-SYN-XDP-",
        "features": ["connection_rate", "unique_destination_ports"],
        "operator": "and",
        "thresholds": {"connection_rate": 15.0, "unique_destination_ports": 8},
        "detection_rule": "block if connection_rate >= 15.0 and unique_destination_ports >= 8",
        "neutralization_action": "drop_network_egress",
        "ebpf_rule": 'SEC("xdp/ingress") if tcp_flags & SYN && rate_limit(ip) > 1000/s => XDP_DROP',
    },
    "syn_cytokine_flood": {
        "id_prefix": "AB-SYN-XDP-",
        "features": ["connection_rate", "unique_destination_ports"],
        "operator": "and",
        "thresholds": {"connection_rate": 15.0, "unique_destination_ports": 8},
        "detection_rule": "block if connection_rate >= 15.0 and unique_destination_ports >= 8",
        "neutralization_action": "drop_network_egress",
        "ebpf_rule": 'SEC("xdp/ingress") if tcp_flags & SYN && rate_limit(ip) > 1000/s => XDP_DROP',
    },
    "c2_beacon": {
        "id_prefix": "AB-EXFIL-DNS-",
        "features": ["beacon_interval_variance", "destination_reputation"],
        "operator": "and",
        "thresholds": {"beacon_interval_variance": 0.3, "destination_reputation": "malicious"},
        "detection_rule": "block if destination matches suspicious C2 exfiltration patterns",
        "neutralization_action": "sever_socket_connection",
        "ebpf_rule": 'SEC("sock_ops") if dport == 53 && packet_entropy > 4.6 => FLUSH_CONN',
    },
    "exfil_parasite": {
        "id_prefix": "AB-EXFIL-DNS-",
        "features": ["beacon_interval_variance", "destination_reputation"],
        "operator": "and",
        "thresholds": {"beacon_interval_variance": 0.3, "destination_reputation": "malicious"},
        "detection_rule": "block if destination matches suspicious C2 exfiltration patterns",
        "neutralization_action": "sever_socket_connection",
        "ebpf_rule": 'SEC("sock_ops") if dport == 53 && packet_entropy > 4.6 => FLUSH_CONN',
    },
    "worm": {
        "id_prefix": "AB-KERNEL-LSM-",
        "features": ["lateral_spread_rate", "peer_connection_fanout"],
        "operator": "and",
        "thresholds": {"lateral_spread_rate": 3.0, "peer_connection_fanout": 2},
        "detection_rule": "block if lateral propagation attempts cross-peer namespace",
        "neutralization_action": "quarantine_source",
        "ebpf_rule": 'SEC("lsm/cred_prepare") if cred->uid == 0 && parent != systemd => TRAP_CONTAINER',
    },
    "worm_ravage": {
        "id_prefix": "AB-KERNEL-LSM-",
        "features": ["lateral_spread_rate", "peer_connection_fanout"],
        "operator": "and",
        "thresholds": {"lateral_spread_rate": 3.0, "peer_connection_fanout": 2},
        "detection_rule": "block if lateral propagation attempts cross-peer namespace",
        "neutralization_action": "quarantine_source",
        "ebpf_rule": 'SEC("lsm/cred_prepare") if cred->uid == 0 && parent != systemd => TRAP_CONTAINER',
    },
    "kernel_blight": {
        "id_prefix": "AB-KERNEL-LSM-",
        "features": ["lateral_spread_rate", "peer_connection_fanout"],
        "operator": "and",
        "thresholds": {"lateral_spread_rate": 3.0, "peer_connection_fanout": 2},
        "detection_rule": "block if lateral propagation attempts cross-peer namespace",
        "neutralization_action": "quarantine_source",
        "ebpf_rule": 'SEC("lsm/cred_prepare") if cred->uid == 0 && parent != systemd => TRAP_CONTAINER',
    },
}


class AntibodySynthesizer:
    """Derives, signs, and packages Digital Antibodies for confirmed security threats."""

    def __init__(self, secret_key: str = "IMMUNE-NET-SUPER-SECRET-ORCHESTRATOR-KEY-v1"):
        self.secret_key = secret_key

    def synthesize(self, threat: ConfirmedThreat) -> Antibody:
        """
        Derive, normalize, and digitally sign an antibody from a confirmed threat.

        Args:
            threat: The confirmed threat instance from the correlation engine.

        Returns:
            Digitally signed Antibody instance.
        """
        scenario = threat.scenario_type
        profile = ANTIBODY_PROFILES.get(scenario, ANTIBODY_PROFILES["cryptominer"])

        short_suffix = compute_hash(threat.threat_id, length=4).replace("0x", "").upper()
        ab_id = f"{profile['id_prefix']}{short_suffix}"

        signature_spec = AntibodySignature(
            features=profile["features"],
            operator=profile["operator"],
            thresholds=profile["thresholds"],
        )

        mitre = get_mitre_technique(scenario)

        antibody = Antibody(
            antibody_id=ab_id,
            schema_version=1,
            threat_type=scenario,
            signature=signature_spec,
            detection_rule=profile["detection_rule"],
            neutralization_action=profile["neutralization_action"],
            created_at=utc_iso_now(),
            source_threat_id=threat.threat_id,
            model_version="detector-v1",
            version=1,
            issuer="immune-net-orchestrator",
            signature_algorithm="hmac-sha256",
            status="active",
            neutralized_count=0,
            ebpf_rule=profile["ebpf_rule"],
            recommendation=get_recommendation(scenario),
            mitre=mitre,
        )

        # Cryptographically sign antibody payload (canonical representation)
        payload_dict = antibody.model_dump()
        antibody.digital_signature = sign_payload(payload_dict, self.secret_key)
        return antibody
