"""
puf_pipeline_1023.py

The paper-scale (1023-bit, BCH(1023,943,17)-class) majority-vote / BCH /
Toeplitz pipeline used specifically for Table 17's "Majority voting, BCH
reconstruction, and 256-bit extraction" row.

This is deliberately separate from shared/fuzzy_extractor.py, which is
NOT touched by this work (existing file; its own BCH parameters, t=8
m=13, target a 64-byte/512-bit raw response and remain what Phase
2/3/4 actually use in the live protocol). This module exists only to
give Task A an honest, paper-parameter-matched pipeline to benchmark.

BCH CAPACITY CAVEAT, read before trusting exact bit counts: bchlib's
Python API is a systematic message+ecc codec (encode(message) -> ecc),
not a raw arbitrary-vector syndrome function. For t=8, m=10 it reports
n=1023 bits and ecc_bits=80 (both exactly matching the paper's
BCH(1023,943,17): 1023-bit codeword, 80 parity bits), but the
byte-aligned message capacity it will safely encode is
floor((n - ecc_bits) / 8) * 8 = 936 bits, seven bits short of the
code's theoretical k=943. Those seven bits are a disclosed
implementation shortfall of bchlib's byte-oriented C API, not a
silent rounding error: this module BCH-protects the first 936 of the
1023 response bits (bytes 0..116 of the 128-byte response buffer) and
carries the remaining 87 bits (plus the fixed padding bit) through
uncorrected. For a timing benchmark this has no material effect (BCH
decode cost is governed by n and t, not by a 7-bit difference in k);
it would matter for a correctness/entropy claim, which is Task C's
job with real HSpice data, not this module's.

The Toeplitz extraction step nonetheless runs over the FULL 1023-bit
response vector, exactly matching Eq. (4)/(5) and Table 11/14's stated
"seeded 2-universal Toeplitz extractor with 256-bit output and
1278-bit public extractor seed."
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import bchlib

import majority_vote
import toeplitz_extractor

_T = 8
_M = 10  # bch.n = 2**10 - 1 = 1023, matching BCH(1023,943,17)'s codeword length

BCH_MESSAGE_BYTES = 117  # 936 bits; see module docstring capacity caveat
RESPONSE_BYTES = majority_vote.RESPONSE_BYTES  # 128 bytes (1023 bits + 1 pad bit)


def _make_bch() -> "bchlib.BCH":
    return bchlib.BCH(t=_T, m=_M)


def fe_gen_1023(raw_reads: list[list[int]]) -> tuple[bytes, bytes, bytes]:
    """
    Enrollment-time path: majority vote -> BCH encode -> Toeplitz extract.

    Returns (K_PUF, bch_ecc, toeplitz_seed). bch_ecc and toeplitz_seed
    together are the public helper data HD = (s, rho) of Eq. (4);
    K_PUF is the 256-bit extracted secret, never stored.
    """
    R = majority_vote.majority_vote(raw_reads)
    bch = _make_bch()
    message = bytearray(R[:BCH_MESSAGE_BYTES])
    ecc = bch.encode(bytes(message))
    seed = toeplitz_extractor.generate_seed()
    k_puf = toeplitz_extractor.extract(R, seed)
    return k_puf, ecc, seed


def fe_rec_1023(raw_reads_noisy: list[list[int]], bch_ecc: bytes,
                 toeplitz_seed: bytes) -> bytes | None:
    """
    Reconstruction-time path: majority vote -> BCH decode/correct ->
    Toeplitz extract. Returns K_PUF, or None if BCH decoding fails
    (more than t=8 bit errors in the protected 936-bit message).
    """
    r_prime = majority_vote.majority_vote(raw_reads_noisy)
    bch = _make_bch()
    message = bytearray(r_prime[:BCH_MESSAGE_BYTES])
    ecc = bytearray(bch_ecc)

    nerr = bch.decode(bytes(message), bytes(ecc))
    if nerr < 0:
        return None
    bch.correct(message, ecc)

    r_corrected = bytes(message) + r_prime[BCH_MESSAGE_BYTES:]
    return toeplitz_extractor.extract(r_corrected, toeplitz_seed)
