"""
seeded_ml_dsa.py

Deterministic ML-DSA key generation from a seed, closing a gap flagged
since the Phase 2 code: liboqs-python's public Signature API only exposes
non-seeded generate_keypair(), but Algorithm 1 and Algorithm 6 both
require ML-DSA.KeyGen(seed_i^sig) to be genuinely deterministic, the same
seed must reproduce the same keypair, since that's what lets the UAV
regenerate its signing key from the RO-PUF instead of storing SK_i.

HOW THIS WORKS: liboqs's C library exposes OQS_randombytes_custom_algorithm(),
which lets you replace its internal randomness source with any function
matching void(uint8_t*, size_t). This module installs a seeded SHAKE256-based
stream as that source, generates a keypair (which liboqs now draws from our
deterministic stream instead of the OS's real RNG), then immediately
switches back to the system RNG so nothing else in the process is
affected. Verified properties (tested before this was ever used in a
protocol script): same seed reproduces the identical (PK, SK) pair;
different seeds produce different pairs; a signature made with the
original key verifies correctly against an independently, later
regenerated public key from the same seed, the actual property Algorithm
6's key-confirmation check depends on.

This is standard-library ctypes plus SHAKE256 (via hashlib), no new
third-party dependency.
"""

import ctypes
import hashlib
import os

import oqs

_LIBOQS_PATHS_TO_TRY = [
    os.environ.get("LIBOQS_LIBRARY", ""),
    "/usr/local/lib/liboqs.so",
    "/usr/local/lib/liboqs.dylib",
    "/opt/homebrew/lib/liboqs.dylib",
    "liboqs.so",
    "liboqs.dylib",
    "liboqs.so.9",
]

_liboqs = None
for _path in _LIBOQS_PATHS_TO_TRY:
    if not _path:
        continue
    try:
        _liboqs = ctypes.CDLL(_path)
        break
    except OSError:
        continue

if _liboqs is None:
    raise ImportError(
        "Could not load liboqs shared library via ctypes. Tried: "
        f"{_LIBOQS_PATHS_TO_TRY}. If it's installed somewhere else on "
        "your Pi, add that path to _LIBOQS_PATHS_TO_TRY above."
    )

_RANDOMBYTES_CB = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)

# Keeps the last-installed ctypes callback object alive. ctypes callbacks
# can be garbage collected out from under the C library if nothing in
# Python still references them, this dict is that reference.
_callback_keepalive = {}


class _DeterministicStream:
    """SHAKE256-based deterministic byte stream from a fixed seed."""

    def __init__(self, seed: bytes):
        self._seed = seed
        self._counter = 0

    def next_bytes(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            block = hashlib.shake_256(
                self._seed + self._counter.to_bytes(8, "big")
            ).digest(64)
            out += block
            self._counter += 1
        return out[:n]


def seeded_keygen(alg_name: str, seed: bytes) -> tuple[bytes, bytes]:
    """
    Deterministically generate a keypair for `alg_name` (e.g. "ML-DSA-65")
    from `seed`. Same seed always returns the same (public_key, secret_key).
    Restores the system RNG before returning, so this has no effect on any
    other randomness used elsewhere in the process.
    """
    stream = _DeterministicStream(seed)

    def _callback(buf_ptr, buf_len):
        data = stream.next_bytes(buf_len)
        ctypes.memmove(buf_ptr, data, buf_len)

    cb = _RANDOMBYTES_CB(_callback)
    _callback_keepalive["current"] = cb

    _liboqs.OQS_randombytes_custom_algorithm(cb)
    try:
        with oqs.Signature(alg_name) as signer:
            pk = signer.generate_keypair()
            sk = signer.export_secret_key()
    finally:
        _liboqs.OQS_randombytes_switch_algorithm(b"system")

    return pk, sk
