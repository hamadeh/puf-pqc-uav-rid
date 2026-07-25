"""Signed, versioned revocation-list validation shared by protocol roles."""

import time

import oqs

import protocol_common as pc
import protocol_messages as pm
import crypto_primitives as cp


def object_id(wire: bytes) -> bytes:
    """CertID, RootID, or KeyID, depending on the canonical input object."""
    return cp.hash_bytes(wire)


def key_id(public_key: bytes) -> bytes:
    return cp.hash_bytes(public_key)


def verify_record(record_wire: bytes, pk_ta: bytes, *,
                  now: int | None = None, minimum_version: int = 0) -> dict:
    body, signature = pm.decode_signed_record(
        record_wire, pm.TYPE_REVOCATION_RECORD, body_max=65535
    )
    with oqs.Signature(pc.ML_DSA_ALG) as verifier:
        if not verifier.verify(body, signature, pk_ta):
            raise ValueError("invalid TA signature on revocation list")
    parsed = pm.decode_revocation_body(body)
    current = int(time.time()) if now is None else int(now)
    if parsed["version"] < minimum_version:
        raise ValueError("revocation-list rollback detected")
    if not parsed["valid_from"] <= current <= parsed["valid_until"]:
        raise ValueError("revocation list is outside its validity interval")
    parsed["record_wire"] = record_wire
    return parsed


def assert_not_revoked(rl: dict, *, cert_id: bytes | None = None,
                       root_id: bytes | None = None,
                       key_id_value: bytes | None = None) -> None:
    checks = (
        (cert_id, rl["revoked_cert_ids"], "certificate"),
        (root_id, rl["revoked_root_ids"], "root"),
        (key_id_value, rl["revoked_key_ids"], "key"),
    )
    for identifier, revoked, label in checks:
        if identifier is not None and identifier in revoked:
            raise ValueError(f"{label} identifier is revoked")
