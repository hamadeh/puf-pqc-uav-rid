"""
fuzzy_extractor.py

FE.Gen / FE.Rec, following the standard fuzzy-extractor pattern of Dodis,
Ostrovsky, Reyzin, and Smith, "Fuzzy Extractors: How to Generate Strong
Keys from Biometrics and Other Noisy Data," SIAM J. Computing 38(1), 2008
(the construction your own paper's reference [28] points to).

This is the syndrome-based variant: helper data is the BCH parity/syndrome
of the raw PUF response, computed once at enrollment and stored reliably.
A later noisy re-read is corrected against that stored syndrome using
bchlib (github.com/jkent/python-bchlib), which wraps a BCH encoder/decoder.
The corrected, exact response is then hashed to produce a uniform secret,
the entropy-extraction step every fuzzy extractor construction requires on
top of error correction alone.

bchlib is a C extension. On the Raspberry Pi 5 (aarch64), `pip install
bchlib` will need to build from source unless a manylinux_aarch64 wheel is
available for your Python version, check this before relying on it; if no
wheel is available you will need build-essential and python3-dev installed
first, and a source build will happen automatically via pip.
"""

import bchlib

from crypto_primitives import hash_bytes

# BCH parameters: t = number of bit errors correctable, m = Galois field
# order (codeword length is 2**m - 1 bits). Providing m lets bchlib select
# a valid primitive polynomial automatically rather than hand-picking one.
#
# SIZING WARNING, verified empirically, not a guess: t must be sized well
# above the *expected* number of bit errors, not just above it. With a
# 64-byte (512-bit) response and t=8, testing at bit_error_rate=0.02
# (expected ~10.2 errors) fails most of the time, since 10.2 > 8. Even at
# bit_error_rate=0.01 (expected ~5.1 errors, comfortably under t=8), 30
# trials only succeeded 25/30 (83%), because binomial variance regularly
# pushes the actual error count above the mean and past t. If you adopt a
# bit-error-rate figure from the RO-PUF literature for your own noise
# model, size t against the tail of the binomial distribution at that
# rate and response length, not the mean, or your fuzzy extractor will
# have a nontrivial, silent failure rate under exactly the conditions it
# exists to handle.
_T = 8
_M = 13


def _make_bch() -> bchlib.BCH:
    return bchlib.BCH(t=_T, m=_M)


def data_capacity_bytes() -> int:
    """Maximum raw-response size (bytes) this BCH configuration can protect."""
    bch = _make_bch()
    return (bch.n // 8) - bch.ecc_bytes


def fe_gen(raw_response: bytes) -> tuple[bytes, bytes]:
    """
    FE.Gen(R) -> (secret, helper_data)

    raw_response: the (noiseless, enrollment-time) PUF response, must fit
    within data_capacity_bytes().
    """
    bch = _make_bch()
    cap = data_capacity_bytes()
    if len(raw_response) > cap:
        raise ValueError(
            f"raw_response is {len(raw_response)} bytes, exceeds this BCH "
            f"configuration's capacity of {cap} bytes; shrink the PUF "
            f"response length or increase m/t."
        )
    # pad to fixed capacity so encode() sees a consistent length
    padded = raw_response.ljust(cap, b"\x00")
    helper_data = bytes(bch.encode(padded))
    secret = hash_bytes(padded)
    return secret, helper_data


def fe_rec(raw_response_noisy: bytes, helper_data: bytes) -> bytes | None:
    """
    FE.Rec(R', helper_data) -> secret, or None if correction fails
    (too many bit errors for this BCH configuration to fix).
    """
    bch = _make_bch()
    cap = data_capacity_bytes()
    padded_noisy = bytearray(raw_response_noisy.ljust(cap, b"\x00"))
    ecc = bytearray(helper_data)

    nerr = bch.decode(bytes(padded_noisy), bytes(ecc))
    if nerr < 0:
        return None  # uncorrectable: more errors than t

    bch.correct(padded_noisy, ecc)
    return hash_bytes(bytes(padded_noisy))
