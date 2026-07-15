"""
protocol_common.py

Shared constants and helpers. COPY THIS FILE, UNCHANGED, TO BOTH MACHINES:
the computer (TA and Verifier roles) and the Pi 5 (UAV role).

Why this matters: domain-separation tags and parameters feed directly into
KDF/hash calls on both sides. If the two machines don't have byte-for-byte
identical copies of this file, derivations will silently diverge, you'll
get "verification failed" errors with no obvious cause. Treat this file
as part of the protocol specification, not implementation detail.

FILE-BASED CHANNEL CONVENTION
Since there's no real network link between the two machines, "sending" a
message means writing a JSON file on one machine and physically copying it
(USB drive, scp, SD card, whatever you have) to the other, then reading it
there. The helpers below (`write_message` / `read_message`) just standardize
the JSON shape and hex-encode binary fields; the actual transport between
machines is manual, on purpose, matching what you asked for.
"""

import json
import os

# ---- Phase 1 parameters (Params, per the paper's Eq. system_params) ----
DELTA_T_SECONDS = 1          # Remote ID pseudonym interval
N_INTERVALS = 16              # n: intervals per Merkle root (small for local testing)
M_ROOTS = 2                    # m: roots per enrollment/renewal cycle
SECURITY_PARAMETER_BITS = 128  # lambda

ML_DSA_ALG = "ML-DSA-65"
ML_KEM_ALG = "ML-KEM-768"

# ---- Domain-separation tags (must match Table: domain-separation labels) ----
TAG_ML_DSA = b"ML-DSA"
TAG_MERKLE_ROOT = b"MerkleRoot"
TAG_INTERVAL_SECRET = b"IntervalSecret"
TAG_RID = b"RID"
TAG_LEAF = b"leaf"
TAG_RID_AUTH = b"RID-Auth"
TAG_LIGHTWEIGHT = b"Lightweight"

# ---- File-based "channel" helpers ----

def _encode_value(value):
    """Recursively hex-encode any bytes found in dicts/lists/tuples."""
    if isinstance(value, bytes):
        return {"__hex__": value.hex()}
    if isinstance(value, dict):
        return {k: _encode_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_encode_value(v) for v in value]
    return value


def _decode_value(value):
    """Recursively reverse _encode_value."""
    if isinstance(value, dict):
        if set(value.keys()) == {"__hex__"}:
            return bytes.fromhex(value["__hex__"])
        return {k: _decode_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode_value(v) for v in value]
    return value


def canonical_json_bytes(fields: dict) -> bytes:
    """
    Deterministic byte serialization of a dict that may contain nested
    bytes values, for use as input to a hash or signature (e.g. H(ReqAuth)).
    Uses the same recursive hex-encoding as write_message, then
    json.dumps(sort_keys=True) so key ordering can never cause two
    machines to compute different bytes for what's logically the same
    message. Do not use str(some_dict) for this, ever, key ordering and
    repr formatting are not guaranteed to round-trip identically across
    processes, this bit us once already in earlier scripts.
    """
    encoded = {key: _encode_value(value) for key, value in fields.items()}
    return json.dumps(encoded, sort_keys=True).encode("utf-8")


def decode_canonical_json(data: bytes) -> dict:
    """Reverses canonical_json_bytes: parses JSON then decodes hex-wrapped bytes."""
    encoded = json.loads(data.decode("utf-8"))
    return _decode_value(encoded)


def write_message(filepath: str, fields: dict) -> None:
    """
    Write a message to a JSON file, standing in for sending it over a real
    channel. Any bytes found anywhere in the structure, including nested
    inside dicts and lists, are hex-encoded automatically. Fields that are
    meant to stay secret (private keys, seeds) should never be passed to
    this function for a file you intend to copy elsewhere, keep those in
    a separate, non-shared file.
    """
    encoded = {key: _encode_value(value) for key, value in fields.items()}

    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(encoded, f, indent=2)


def read_message(filepath: str) -> dict:
    """Read a message written by write_message(), decoding hex fields back to bytes."""
    with open(filepath, "r") as f:
        encoded = json.load(f)

    return {key: _decode_value(value) for key, value in encoded.items()}
