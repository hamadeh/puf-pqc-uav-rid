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
import hashlib
import os
import struct

import crypto_primitives as _cp

# ---- Phase 1 parameters (Params, per the paper's Eq. system_params) ----
PROTOCOL_VERSION = 1
DELTA_T_SECONDS = 1          # Remote ID pseudonym interval
N_INTERVALS = 1024             # n: publication-scale default; Phase 1 accepts --n
M_ROOTS = 2                    # m: roots per enrollment/renewal cycle
SECURITY_PARAMETER_BITS = 128  # lambda
FRESHNESS_TOLERANCE_SECONDS = 30
MAX_REQUEST_BYTES = 64 * 1024

ML_DSA_ALG = "ML-DSA-65"
ML_KEM_ALG = "ML-KEM-768"

# ---- Domain-separation tags (Table 5: domain-separation labels used in
# KDF and hash calls). TAG_LIGHTWEIGHT is deliberately absent: it isn't
# in Table 5 at all, it was a leftover from an earlier draft's
# lightweight/strong mode split, which the paper's final Algorithm 5+6
# doesn't have (Phase 4 always runs the full sequence; see Section
# III.H: "The protocol has no lower-assurance branch").
TAG_PUF_SIGN = b"PUF-SIGN"
TAG_PUF_MERKLE = b"PUF-MERKLE"
TAG_MERKLE_ROOT = b"MerkleRoot"
TAG_INTERVAL_SECRET = b"IntervalSecret"
TAG_RID = b"RID"
TAG_RID_AUTH = b"RID-Auth"
TAG_ROOT_REQUEST = b"ROOT-REQUEST-v1"
TAG_ROOT_AUTH = b"ROOT-AUTH-v1"
TAG_VERIFIER_REQUEST = b"RID-VERIFIER-REQUEST-v1"
TAG_UAV_RESPONSE = b"RID-UAV-RESPONSE-v1"
TAG_AEAD_AD = b"RID-AEAD-AD-v1"
TAG_REQID = b"ReqID"
TAG_AEAD_NONCE = b"AEAD-Nonce"


def u16(value: int) -> bytes:
    if value < 0 or value > 0xFFFF:
        raise ValueError("value outside uint16 range")
    return struct.pack("!H", value)


def u32(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError("value outside uint32 range")
    return struct.pack("!I", value)


def u64(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("value outside uint64 range")
    return struct.pack("!Q", value)


def encode_labeled(label: bytes, *parts: bytes) -> bytes:
    """
    Versioned, length-delimited encoding for KDF and hash inputs.

    Each field is typed by its fixed position under ``label`` and has a
    network-order length.  This replaces ambiguous byte concatenation.
    """
    if not isinstance(label, bytes) or not label or len(label) > 255:
        raise ValueError("domain label must contain 1..255 bytes")
    encoded = b"URID" + bytes([PROTOCOL_VERSION, len(label)]) + label + u16(len(parts))
    for part in parts:
        if not isinstance(part, bytes):
            raise TypeError("canonical labeled fields must be bytes")
        encoded += u32(len(part)) + part
    return encoded


def hash_labeled(label: bytes, *parts: bytes) -> bytes:
    return _cp.hash_bytes(encode_labeled(label, *parts))


def kdf_labeled(label: bytes, *parts: bytes) -> bytes:
    return _cp.kdf(encode_labeled(label, *parts))


def shake256_labeled(label: bytes, *parts: bytes, output_bytes: int = 32) -> bytes:
    return hashlib.shake_256(encode_labeled(label, *parts)).digest(output_bytes)


def derive_purpose_secrets(k_puf: bytes, ctx_i: bytes) -> tuple[bytes, bytes]:
    if len(k_puf) != 32:
        raise ValueError("K_PUF must be 32 bytes")
    return (
        shake256_labeled(TAG_PUF_SIGN, k_puf, ctx_i),
        shake256_labeled(TAG_PUF_MERKLE, k_puf, ctx_i),
    )

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
    """ReqID = Trunc128(H256(Enc("ReqID", ReqAuthWire)))."""
    return hash_labeled(TAG_REQID, req_auth_bytes)[:16]


def compute_aead_nonce(req_id: bytes, ct: bytes) -> bytes:
    """N_A = Trunc128(H256(Enc("AEAD-Nonce", ReqID, ct)))."""
    return hash_labeled(TAG_AEAD_NONCE, req_id, ct)[:16]
