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

import crypto_primitives as _cp

# ---- Phase 1 parameters (Params, per the paper's Eq. system_params) ----
DELTA_T_SECONDS = 1          # Remote ID pseudonym interval
N_INTERVALS = 1024             # n: publication-scale default; Phase 1 accepts --n
M_ROOTS = 2                    # m: roots per enrollment/renewal cycle
SECURITY_PARAMETER_BITS = 128  # lambda

ML_DSA_ALG = "ML-DSA-65"
ML_KEM_ALG = "ML-KEM-768"

# ---- Domain-separation tags (Table 5: domain-separation labels used in
# KDF and hash calls). TAG_LIGHTWEIGHT is deliberately absent: it isn't
# in Table 5 at all, it was a leftover from an earlier draft's
# lightweight/strong mode split, which the paper's final Algorithm 5+6
# doesn't have (Phase 4 always runs the full sequence; see Section
# III.H: "The protocol has no lower-assurance branch").
TAG_ML_DSA = b"ML-DSA"
TAG_MERKLE_ROOT = b"MerkleRoot"
TAG_INTERVAL_SECRET = b"IntervalSecret"
TAG_RID = b"RID"
TAG_LEAF = b"leaf"
TAG_NODE = b"node"
TAG_RID_AUTH = b"RID-Auth"
TAG_AUTH_TRANSCRIPT = b"RID-UAV-Auth-v1"
TAG_STATE = b"state"
TAG_REQID = b"ReqID"
TAG_AEAD_NONCE = b"AEAD-Nonce"

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


def serialize_message_bytes(fields: dict) -> bytes:
    """
    Serialize the exact JSON representation used by write_message().

    This public in-memory form lets benchmarks include serialization in
    complete software latency and report the exact transmitted byte size
    without creating temporary files.
    """
    encoded = {key: _encode_value(value) for key, value in fields.items()}
    return json.dumps(encoded, indent=2).encode("utf-8")


def deserialize_message_bytes(data: bytes) -> dict:
    """Inverse of serialize_message_bytes(), without filesystem I/O."""
    encoded = json.loads(data.decode("utf-8"))
    return {key: _decode_value(value) for key, value in encoded.items()}


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


# ---- Eq. (10)-(11): ReqID and the deterministic AEAD nonce ----
#
# Defined once here, rather than re-derived independently in each phase
# script, precisely because (per this file's own docstring) any
# byte-level divergence between the UAV and verifier sides silently
# breaks verification. Both sides must call these on the identical
# canonical bytes (canonical_json_bytes(req_auth) for req_auth_bytes).

def compute_req_id(req_auth_bytes: bytes) -> bytes:
    """ReqID = Trunc128(H256("ReqID" || ReqAuthWire)), Eq. (10)."""
    return _cp.hash_bytes(TAG_REQID + req_auth_bytes)[:16]


def compute_aead_nonce(req_id: bytes, ct: bytes) -> bytes:
    """N_A = Trunc128(H256("AEAD-Nonce" || ReqID || ct)), Eq. (11)."""
    return _cp.hash_bytes(TAG_AEAD_NONCE + req_id + ct)[:16]
