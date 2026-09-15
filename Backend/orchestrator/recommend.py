"""
Security Hardening Recommendation Engine for IMMUNE-NET.
Provides human-readable, actionable post-incident guidance for system administrators
and SOC response teams based on confirmed attack classification.
"""

from typing import Dict

RECOMMENDATIONS: Dict[str, str] = {
    "cryptominer": "Restrict outbound connections to known mining-pool IP ranges. Enforce process allowlisting on this node type. Monitor for sustained CPU utilization above 90% as an early indicator.",
    "crypto_ransomware": "Restrict outbound connections to known mining-pool IP ranges. Enforce process allowlisting on this node type. Monitor for sustained CPU utilization above 90% as an early indicator.",
    "port_scan": "Rate-limit inbound connections per source IP. Enable connection-attempt throttling (fail2ban-style) on affected node types. Review firewall rules for unnecessarily open ports.",
    "syn_cytokine_flood": "Rate-limit inbound connections per source IP. Enable connection-attempt throttling (fail2ban-style) on affected node types. Review firewall rules for unnecessarily open ports.",
    "c2_beacon": "Audit outbound firewall rules for periodic low-volume traffic to unrecognized external IPs. Consider DNS-layer filtering for known C2 domains. Flag fixed-interval beaconing patterns as high-priority review items.",
    "exfil_parasite": "Audit outbound firewall rules for periodic low-volume traffic to unrecognized external IPs. Consider DNS-layer filtering for known C2 domains. Flag fixed-interval beaconing patterns as high-priority review items.",
    "worm_ravage": "Segment the network to limit lateral movement between nodes of the same type. Patch the specific vector this worm exploited across all nodes immediately, not just the quarantined one. Review east-west traffic rules between agents.",
    "worm": "Segment the network to limit lateral movement between nodes of the same type. Patch the specific vector this worm exploited across all nodes immediately, not just the quarantined one. Review east-west traffic rules between agents.",
    "kernel_blight": "Segment the network to limit lateral movement between nodes of the same type. Patch the specific vector this worm exploited across all nodes immediately, not just the quarantined one. Review east-west traffic rules between agents.",
}

DEFAULT_RECOMMENDATION: str = "Review the incident's feature vector manually; no pre-built recommendation exists for this attack signature yet."


def get_recommendation(attack_type: str) -> str:
    """
    Retrieve actionable post-incident security hardening recommendations for an attack type.

    Args:
        attack_type: Attack or threat scenario name.

    Returns:
        Guidance string with concrete remediation steps.
    """
    if not attack_type:
        return DEFAULT_RECOMMENDATION
    return RECOMMENDATIONS.get(str(attack_type).strip().lower(), DEFAULT_RECOMMENDATION)