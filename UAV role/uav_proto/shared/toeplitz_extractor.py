"""
toeplitz_extractor.py

Ext_rho(.): the seeded 2-universal Toeplitz extractor from Eq. (4)/(5) of
the paper, mapping the 1023-bit RO-PUF response vector to a 256-bit
K_PUF, with a 1278-bit public extractor seed rho (Table 11: "seeded
2-universal Toeplitz extractor with 256-bit output and 1278-bit public
extractor seed").

CONSTRUCTION. For input length n=1023 and output length m=256, a Toeplitz
matrix T is an m x n binary matrix built from a single seed of
n + m - 1 = 1278 bits, where T[i][j] = rho[i + j] (0-indexed). Every
diagonal of T is therefore constant, which is exactly what makes this a
2-universal hash family in rho (see e.g. Krawczyk 1994; this is the
standard leftover-hash-lemma extractor construction the paper's
reference [32] uses). The output is K_PUF = T . R over GF(2), an
m-bit vector.

IMPLEMENTATION NOTE ON SPEED. A naive bit-by-bit matrix-vector product
is O(n*m) individual GF(2) multiply-accumulates. Instead, row i of T is
just rho shifted by i bits and masked to n bits, so each output bit is
the parity of (rho >> i) & R, computed with Python's native big-integer
AND plus a popcount. Representing rho and R as single Python ints
(arbitrary precision, native C-speed bit ops) makes this fast enough for
repeated per-trial benchmarking: 256 shift+AND+popcount operations over
~1023-bit integers, no explicit matrix ever materialized.

BIT ORDER CONVENTION. R is supplied as a big-endian bitstring packed
into bytes (bit 0 = MSB of byte 0, matching majority_vote.py's output).
rho is supplied the same way, at N_IN + M_OUT - 1 = 1278 bits (160
bytes, with the 2 highest bits of the first byte unused/zero, since
160*8 = 1280). Only the low 1278 bits of the seed buffer are used.
"""

import secrets

N_IN = 1023
M_OUT = 256
SEED_BITS = N_IN + M_OUT - 1  # 1278, per Table 11
SEED_BYTES = (SEED_BITS + 7) // 8  # 160 bytes; top 2 bits of byte 0 unused


def _bytes_to_int(data: bytes, nbits: int) -> int:
    """Big-endian bytes -> int, keeping only the low nbits bits."""
    value = int.from_bytes(data, "big")
    return value & ((1 << nbits) - 1)


def generate_seed() -> bytes:
    """A fresh public 1278-bit Toeplitz seed rho, SEED_BYTES long."""
    return secrets.token_bytes(SEED_BYTES)


def extract(response_bits: bytes, seed: bytes) -> bytes:
    """
    Ext_rho(R) -> 256-bit K_PUF.

    response_bits: the (corrected) 1023-bit response vector R, packed
    big-endian into ceil(1023/8) = 128 bytes; only the top 1023 bits are
    read, the trailing padding bit is ignored.
    seed: SEED_BYTES-byte public Toeplitz seed from generate_seed().
    """
    if len(seed) < SEED_BYTES:
        raise ValueError(f"seed must be at least {SEED_BYTES} bytes ({SEED_BITS} bits)")

    r_int = _bytes_to_int(response_bits, N_IN)
    rho_int = _bytes_to_int(seed, SEED_BITS)

    mask_n = (1 << N_IN) - 1
    out_bits = 0
    for i in range(M_OUT):
        row = (rho_int >> i) & mask_n
        parity = (row & r_int).bit_count() & 1
        out_bits = (out_bits << 1) | parity

    return out_bits.to_bytes(M_OUT // 8, "big")
