"""
Seeded two-universal Toeplitz extraction for the selected 950-bit response.

For n=950 input bits and m=256 output bits, the public seed contains
n+m-1=1205 bits.  Packed values are unsigned big-endian integers with unused
high bits fixed to zero.
"""

import secrets

N_IN = 950
M_OUT = 256
SEED_BITS = N_IN + M_OUT - 1
SEED_BYTES = (SEED_BITS + 7) // 8


def generate_seed() -> bytes:
    value = secrets.randbits(SEED_BITS)
    return value.to_bytes(SEED_BYTES, "big")


def extract_int(response: int, seed: bytes) -> bytes:
    """Extract 256 bits from one integer containing exactly 950 response bits."""
    if response < 0 or response >= (1 << N_IN):
        raise ValueError(f"response must fit in {N_IN} bits")
    if len(seed) != SEED_BYTES:
        raise ValueError(f"seed must be exactly {SEED_BYTES} bytes")
    seed_value = int.from_bytes(seed, "big")
    if seed_value >= (1 << SEED_BITS):
        raise ValueError("unused high bits in the Toeplitz seed must be zero")

    mask = (1 << N_IN) - 1
    output = 0
    for row_index in range(M_OUT):
        row = (seed_value >> row_index) & mask
        output = (output << 1) | ((row & response).bit_count() & 1)
    return output.to_bytes(M_OUT // 8, "big")


def extract(response_bits: bytes, seed: bytes) -> bytes:
    """Packed-byte wrapper retained for benchmark and fixture callers."""
    expected_bytes = (N_IN + 7) // 8
    if len(response_bits) != expected_bytes:
        raise ValueError(f"response must be exactly {expected_bytes} bytes")
    response = int.from_bytes(response_bits, "big")
    return extract_int(response, seed)
