"""
Cryptographic signing and verification utilities for IMMUNE-NET antibodies and quarantine commands.
"""

import hmac
import hashlib
import json
from typing import Any, Dict

DEFAULT_SECRET_KEY = "IMMUNE-NET-SUPER-SECRET-ORCHESTRATOR-KEY-v1"

SIGNATURE_EXCLUDED_FIELDS = frozenset({
    "digital_signature",
    # Volatile / runtime-derived fields are NOT part of an antibody's signed identity:
    # excluding them keeps signatures deterministic and stable as antibodies age
    # (effective_confidence / decay_status decay over time) or neutralize attacks
    # (neutralized_count increments), without invalidating prior authentications.
    "effective_confidence",
    "decay_status",
    "neutralized_count",
})


def canonical_json(data: Dict[str, Any]) -> bytes:
    """Produce deterministic UTF-8 bytes for JSON signing.

    Runtime/derived fields listed in ``SIGNATURE_EXCLUDED_FIELDS`` are stripped
    before hashing so that time-decay (effective_confidence, decay_status) and
    mutable counters (neutralized_count) cannot invalidate a valid signature.
    """
    clean_data = {k: v for k, v in data.items() if k not in SIGNATURE_EXCLUDED_FIELDS}

    def _default(obj: Any) -> str:
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        return str(obj)

    return json.dumps(clean_data, sort_keys=True, separators=(',', ':'), default=_default).encode('utf-8')

def sign_payload(data: Dict[str, Any], secret_key: str = DEFAULT_SECRET_KEY) -> str:
    """Generate HMAC-SHA256 signature for payload."""
    payload_bytes = canonical_json(data)
    signature = hmac.new(secret_key.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()
    return signature

def verify_payload_signature(data: Dict[str, Any], signature: str, secret_key: str = DEFAULT_SECRET_KEY) -> bool:
    """Verify HMAC-SHA256 signature against payload."""
    if not signature:
        return False
    expected = sign_payload(data, secret_key)
    return hmac.compare_digest(expected, signature)

def compute_hash(data: Any, length: int = 8) -> str:
    """Compute short hex hash prefix for display/audit."""
    raw = json.dumps(data, sort_keys=True) if isinstance(data, (dict, list)) else str(data)
    digest = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    return f"0x{digest[:length]}"
