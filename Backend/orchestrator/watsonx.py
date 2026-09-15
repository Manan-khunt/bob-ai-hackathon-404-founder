"""
Watsonx AI Threat Intelligence and Narrative Enrichment Adapter.
Provides optional natural-language enrichment for incident narratives and BLUF summaries
using IBM watsonx.ai Granite models, with deterministic local fallback on any failure.
"""

import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("orchestrator.watsonx")

# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------

def _has_watsonx_credentials() -> bool:
    """Check if Watsonx credentials are configured."""
    return bool(os.getenv("WATSONX_PROJECT_ID") and os.getenv("WATSONX_API_KEY"))


def _get_watsonx_credentials() -> Optional[Dict[str, str]]:
    """Build credentials dict from environment variables."""
    api_key = os.getenv("WATSONX_API_KEY")
    project_id = os.getenv("WATSONX_PROJECT_ID")
    url = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
    model_id = os.getenv("WATSONX_MODEL_ID", "ibm/granite-3-8b-instruct")

    if not api_key or not project_id:
        return None

    return {
        "api_key": api_key,
        "project_id": project_id,
        "url": url,
        "model_id": model_id,
    }


# ---------------------------------------------------------------------------
# Granite model call
# ---------------------------------------------------------------------------

def _call_granite(prompt: str, max_new_tokens: int = 250) -> Optional[str]:
    """
    Call IBM watsonx.ai Granite model with a prompt.

    Returns the generated text, or None on any failure.
    Credentials are checked first; SDK import is attempted lazily.
    """
    creds = _get_watsonx_credentials()
    if not creds:
        return None

    try:
        from ibm_watsonx_ai.foundation_models import ModelInference
        from ibm_watsonx_ai import Credentials

        credentials = Credentials(
            api_key=creds["api_key"],
            url=creds["url"],
        )

        model = ModelInference(
            model_id=creds["model_id"],
            credentials=credentials,
            project_id=creds["project_id"],
        )

        result = model.generate_text(
            prompt=prompt,
            params={
                "max_new_tokens": max_new_tokens,
                "temperature": 0.1,
                "top_p": 0.9,
                "repetition_penalty": 1.1,
            },
        )

        if isinstance(result, str) and len(result.strip()) > 20:
            return result.strip()
        return None

    except ImportError:
        logger.warning(
            "[WATSONX] ibm-watsonx-ai SDK not installed. "
            "Install with: pip install ibm-watsonx-ai"
        )
        return None
    except Exception as exc:
        logger.warning(f"[WATSONX] Granite model call failed: {exc}")
        return None


# ---------------------------------------------------------------------------
# BLUF Generation via Granite
# ---------------------------------------------------------------------------

def generate_watsonx_bluf(
    threat_context: Dict[str, Any],
    explanation_data: Optional[Dict[str, Any]] = None,
    mitre_data: Optional[Dict[str, str]] = None,
    apt_data: Optional[Dict[str, Any]] = None,
    blast_radius_data: Optional[Dict[str, Any]] = None,
    containment_status: str = "active",
    immune_memory_status: str = "pending",
) -> Optional[str]:
    """
    Generate a 3-sentence commander BLUF briefing using IBM watsonx.ai Granite.

    The prompt receives complete threat context and explanation data.
    Granite is instructed to summarize facts only — never invent data.

    Args:
        threat_context: Dict with threat_type, severity, confidence, node_id,
            cpu_usage, memory_usage, entropy, process, connections, etc.
        explanation_data: Output of explain.generate_explanation() with feature contributions.
        mitre_data: MITRE ATT&CK technique mapping dict.
        apt_data: APT attribution result dict.
        blast_radius_data: Blast radius prediction result.
        containment_status: Current containment state.
        immune_memory_status: Digital antibody / immune memory status.

    Returns:
        3-sentence BLUF string, or None if Watsonx is unavailable/fails.
    """
    if not _has_watsonx_credentials():
        return None

    # Build the prompt with strict fact constraints
    context_parts = []
    context_parts.append(f"Threat type: {threat_context.get('threat_type', 'unknown')}")
    context_parts.append(f"Severity: {threat_context.get('severity', 'unknown')}")
    context_parts.append(f"Confidence: {threat_context.get('confidence', 'unknown')}")
    context_parts.append(f"Affected node: {threat_context.get('node_id', 'unknown')}")

    if threat_context.get("cpu_usage"):
        context_parts.append(f"CPU usage: {threat_context['cpu_usage']}%")
    if threat_context.get("memory_usage"):
        context_parts.append(f"Memory usage: {threat_context['memory_usage']}%")
    if threat_context.get("entropy"):
        context_parts.append(f"Entropy: {threat_context['entropy']}")
    if threat_context.get("process"):
        context_parts.append(f"Process: {threat_context['process']}")
    if threat_context.get("connections"):
        context_parts.append(f"Network connections: {threat_context['connections']}")
    if threat_context.get("connection_rate"):
        context_parts.append(f"Connection rate: {threat_context['connection_rate']}/s")

    if mitre_data:
        context_parts.append(
            f"MITRE ATT&CK: {mitre_data.get('technique_id', 'unknown')} — "
            f"{mitre_data.get('technique_name', 'unknown')} ({mitre_data.get('tactic', 'unknown')})"
        )

    if apt_data and apt_data.get("top_match"):
        tm = apt_data["top_match"]
        context_parts.append(
            f"APT attribution: {tm.get('name', 'unclassified')} "
            f"({round(tm.get('confidence_pct', 0), 1)}% confidence)"
        )

    if explanation_data and explanation_data.get("explanation"):
        indicators = []
        for c in explanation_data["explanation"][:3]:
            if c.get("normalized_contribution", 0) > 0:
                indicators.append(
                    f"{c['feature'].replace('_', ' ')} {c['value']} "
                    f"({round(c['normalized_contribution'] * 100, 1)}% contribution)"
                )
        if indicators:
            context_parts.append(f"Primary anomaly indicators: {'; '.join(indicators)}")

    if blast_radius_data:
        chain = blast_radius_data.get("propagation_chain", [])
        if chain:
            affected = [e.get("node_id", "?") for e in chain[:3]]
            context_parts.append(f"Potentially affected peers: {', '.join(affected)}")

    context_parts.append(f"Containment: {containment_status}")
    context_parts.append(f"Immune memory: {immune_memory_status}")

    context_block = "\n".join(context_parts)

    prompt = (
        "You are a cybersecurity threat intelligence analyst generating a Bottom Line Up Front (BLUF) briefing.\n\n"
        "RULES:\n"
        "- Produce exactly 3 sentences.\n"
        "- Sentence 1: Severity, threat type, key behavioral indicators (use provided numbers).\n"
        "- Sentence 2: Affected endpoints, blast radius, and containment status.\n"
        "- Sentence 3: Recommended response action.\n"
        "- ONLY use facts provided below. If information is unavailable, say 'not available'.\n"
        "- Do NOT invent IP addresses, threat actors, or MITRE techniques.\n"
        "- Do NOT fabricate benchmark numbers.\n\n"
        "THREAT EVIDENCE:\n"
        f"{context_block}\n\n"
        "Generate a concise 3-sentence commander BLUF briefing:"
    )

    result = _call_granite(prompt, max_new_tokens=200)
    if result:
        # Validate: must contain at least 2 sentences (period-separated)
        sentences = [s.strip() for s in result.split(".") if s.strip()]
        if len(sentences) >= 2:
            return result.strip()

    return None


# ---------------------------------------------------------------------------
# Narrative Generation (DETAILS section enrichment)
# ---------------------------------------------------------------------------

def generate_watsonx_narrative(
    attack_type: str,
    node_id: str,
    technique_id: str,
    technique_name: str,
    tactic: str,
    recommendation: str,
) -> Optional[str]:
    """
    Generate an AI-enriched analytical narrative for the DETAILS section of a BLUF summary.
    Falls back silently to None if Watsonx is unavailable or fails.

    Args:
        attack_type: Name of detected attack scenario.
        node_id: Compromised host/agent identifier.
        technique_id: MITRE technique ID (e.g. T1496).
        technique_name: MITRE technique name.
        tactic: MITRE tactic.
        recommendation: Hardening guidance string.

    Returns:
        Optional natural-language string.
    """
    if not _has_watsonx_credentials():
        return None

    prompt = (
        f"Write a single analytical sentence for a threat incident.\n"
        f"Attack type: {attack_type}\n"
        f"Affected host: {node_id}\n"
        f"MITRE technique: {technique_name} ({technique_id}) under the {tactic} tactic\n"
        f"Recommendation: {recommendation}\n\n"
        f"Rules: Use only the facts above. Do not add IPs, actors, or unmentioned techniques. "
        f"Output one concise sentence:"
    )

    return _call_granite(prompt, max_new_tokens=100)


# ---------------------------------------------------------------------------
# Threat Classification Narrative
# ---------------------------------------------------------------------------

def classify_threat(threat_type: str, evidence: dict) -> dict:
    """
    Return classified threat structure with watsonx narrative if configured, or local rule fallback.

    Args:
        threat_type: Attack category name.
        evidence: Dictionary of telemetry biomarker evidence.

    Returns:
        Dict with 'class' and 'narrative'.
    """
    if _has_watsonx_credentials():
        narrative = _call_granite(
            f"Classify this threat evidence:\n"
            f"Type: {threat_type}\n"
            f"Evidence keys: {', '.join(str(k) for k in evidence.keys())}\n"
            f"One sentence classification:",
            max_new_tokens=80,
        )
        if narrative:
            return {"class": threat_type, "narrative": narrative}

    return {
        "class": threat_type,
        "narrative": f"Local rule-based classifier matched {threat_type} evidence: {sorted(evidence)}",
    }
