"""
Threat Actor Fingerprinting Engine for IMMUNE-NET.
Attribuates confirmed threat technique sets to known adversary groups (APTs) using
weighted cosine similarity against pre-loaded MITRE ATT&CK technique profiles.
"""

from typing import Dict, Any, List, Set, Optional
import math

# Weighted MITRE technique profiles per known threat actor.
# Weights represent how strongly that group relies on each technique (0.0 - 1.0).
APT_PROFILES: Dict[str, Dict[str, float]] = {
    "APT41": {
        "T1496": 0.95,
        "T1071": 0.85,
        "T1210": 0.70,
        "T1059": 0.60,
    },
    "FIN7": {
        "T1071": 0.90,
        "T1056": 0.85,
        "T1203": 0.75,
        "T1486": 0.65,
    },
    "Lazarus": {
        "T1496": 0.80,
        "T1041": 0.90,
        "T1027": 0.85,
        "T1486": 0.70,
    },
    "CozyBear": {
        "T1071": 0.95,
        "T1078": 0.85,
        "T1114": 0.80,
        "T1560": 0.70,
    },
    "ScatteredSpider": {
        "T1078": 0.90,
        "T1210": 0.75,
        "T1071": 0.80,
        "T1059": 0.65,
    },
}

APT_DESCRIPTIONS: Dict[str, str] = {
    "APT41": "Prolific state-sponsored cybercrime group blurring espionage and theft, known for "
             "resource hijacking and dual-use exploitation against supply chains.",
    "FIN7": "Financially motivated criminal group deploying spear-phishing and point-of-sale "
            "implants, later pivoting to ransomware and data exfiltration.",
    "Lazarus": "North Korean state-sponsored group targeting financial infrastructure, "
               "cryptocurrency platforms, and defense networks with stealthy C2.",
    "CozyBear": "Cozy Bear (APT29) conducts targeted espionage via credential harvesting, "
                "legitimate-account abuse, and encrypted C2 over standard protocols.",
    "ScatteredSpider": "SYSTEMBCAL aggressive initial-access group abusing valid accounts, "
                       "helpdesk social engineering, and persistence tradecraft.",
}

# Scenario -> plausible observed technique set. Enriches attribution for incidents
# that only expose a single canonical technique id.
SCENARIO_TECHNIQUES: Dict[str, List[str]] = {
    "cryptominer": ["T1496", "T1071", "T1059"],
    "crypto_ransomware": ["T1486", "T1496", "T1071"],
    "port_scan": ["T1046", "T1071"],
    "syn_cytokine_flood": ["T1046", "T1071"],
    "c2_beacon": ["T1071", "T1078", "T1041"],
    "exfil_parasite": ["T1071", "T1041", "T1027"],
    "worm": ["T1210", "T1059", "T1071"],
    "worm_ravage": ["T1210", "T1059", "T1071"],
    "kernel_blight": ["T1210", "T1059", "T1027"],
}


def detected_techniques_for(scenario_type: Optional[str], mitre: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Expand a scenario + MITRE mapping into an observed technique id list.

    Args:
        scenario_type: Canonical attack scenario name.
        mitre: Optional MITRE technique mapping dict from a threat/incident.

    Returns:
        List of MITRE technique IDs observed for the incident.
    """
    techniques: List[str] = []
    if scenario_type:
        techniques.extend(SCENARIO_TECHNIQUES.get(scenario_type, []))
    if mitre:
        tech_id = mitre.get("technique_id")
        if tech_id and tech_id != "UNKNOWN" and tech_id not in techniques:
            techniques.append(tech_id)
    return techniques or (["UNKNOWN"])


def _cosine_similarity(detected: Set[str], profile: Dict[str, float]) -> float:
    """
    Cosine similarity between a binary detected-technique set vector and a
    weighted APT profile vector over the union of all technique ids.
    """
    if not detected:
        return 0.0
    profile_norm = math.sqrt(sum(w * w for w in profile.values())) or 1.0
    query_norm = math.sqrt(len(detected)) or 1.0
    overlap = sum(weight for tech, weight in profile.items() if tech in detected)
    return overlap / (profile_norm * query_norm)


def fingerprint_threat_actor(detected_techniques: List[str]) -> List[Dict[str, Any]]:
    """
    Attribute a set of detected MITRE techniques to the top-3 known threat actors.

    Args:
        detected_techniques: List of MITRE technique IDs observed during the incident.

    Returns:
        Top 3 ranked matches, each: {name, confidence_pct, matched_techniques, description}.
    """
    detected = {str(t).strip().upper() for t in detected_techniques if t}
    if not detected:
        detected = {"UNKNOWN"}

    ranked: List[Dict[str, Any]] = []
    for name, profile in APT_PROFILES.items():
        sim = _cosine_similarity(detected, profile)
        matched = sorted([t for t in profile if t in detected], key=lambda t: profile[t], reverse=True)
        ranked.append({
            "name": name,
            "confidence_pct": round(sim * 100.0, 1),
            "matched_techniques": matched,
            "description": APT_DESCRIPTIONS.get(name, ""),
        })

    ranked.sort(key=lambda x: x["confidence_pct"], reverse=True)
    return ranked[:3]