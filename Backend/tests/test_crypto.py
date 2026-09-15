"""Unit tests for cryptographic signing and verification."""

import pytest
from common.crypto_utils import sign_payload, verify_payload_signature, compute_hash

def test_sign_and_verify_valid():
    payload = {
        "antibody_id": "AB-CRYPTO-1",
        "threat_type": "cryptominer",
        "threshold": 75.0
    }
    sig = sign_payload(payload)
    assert isinstance(sig, str)
    assert len(sig) == 64  # SHA256 hex string
    assert verify_payload_signature(payload, sig) is True

def test_verify_detects_tampering():
    payload = {
        "antibody_id": "AB-CRYPTO-1",
        "threat_type": "cryptominer",
        "threshold": 75.0
    }
    sig = sign_payload(payload)

    # Tampered payload
    tampered_payload = dict(payload)
    tampered_payload["threshold"] = 50.0

    assert verify_payload_signature(tampered_payload, sig) is False

def test_verify_detects_invalid_key():
    payload = {"foo": "bar"}
    sig = sign_payload(payload, secret_key="key-A")
    assert verify_payload_signature(payload, sig, secret_key="key-B") is False
