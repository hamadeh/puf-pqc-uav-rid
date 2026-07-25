"""
PUF.Enroll / PUF.Reconstruct for the manuscript's selected-response interface.

Enrollment majority-votes 1023 comparisons, retains the device-specific
top-950 positions meeting the fixed 0.5% normalized-margin threshold, creates
a code-offset helper using shortened BCH(950,870), and applies a seeded
950-to-256-bit Toeplitz extractor.  Reconstruction reuses the public mask and
helper data and fails when BCH decoding cannot recover a valid codeword.

The helper data is public and contains the selection mask, code offset,
Toeplitz seed, and fixed reconstruction parameters.  Its contents must be
included when assessing conditional PUF entropy.
"""

import secrets

import bch950
import challenge_schedule
import majority_vote
import puf_emulated
import toeplitz_extractor

MARGIN_THRESHOLD = 0.005
CANDIDATE_BITS = 1023
SELECTED_BITS = 950
READS_PER_CHALLENGE = 9
HELPER_VERSION = 1
_SELECTED_BYTES = (SELECTED_BITS + 7) // 8


def _majority_bits(raw_reads: list[list[int]]) -> list[int]:
    packed = majority_vote.majority_vote(raw_reads)
    return [
        (packed[index // 8] >> (7 - index % 8)) & 1
        for index in range(CANDIDATE_BITS)
    ]


def _bits_to_int(bits: list[int]) -> int:
    value = 0
    for bit in bits:
        if bit not in (0, 1):
            raise ValueError("response entries must be binary")
        value = (value << 1) | bit
    return value


def _pack_fixed(value: int, bit_count: int) -> bytes:
    if value < 0 or value >= (1 << bit_count):
        raise ValueError(f"value does not fit in {bit_count} bits")
    return value.to_bytes((bit_count + 7) // 8, "big")


def _unpack_fixed(data: bytes, bit_count: int) -> int:
    expected = (bit_count + 7) // 8
    if len(data) != expected:
        raise ValueError(f"expected {expected} bytes for {bit_count} bits")
    value = int.from_bytes(data, "big")
    if value >= (1 << bit_count):
        raise ValueError("unused high padding bits must be zero")
    return value


def select_top950(margins: list[float]) -> list[int]:
    """Return a deterministic, schedule-ordered mask for eligible positions."""
    if len(margins) != CANDIDATE_BITS:
        raise ValueError(f"expected {CANDIDATE_BITS} enrollment margins")
    eligible = [
        (float(margin), index)
        for index, margin in enumerate(margins)
        if float(margin) >= MARGIN_THRESHOLD
    ]
    if len(eligible) < SELECTED_BITS:
        raise ValueError(
            f"PUF enrollment rejected: only {len(eligible)} positions meet "
            f"the {100 * MARGIN_THRESHOLD:.1f}% margin threshold"
        )
    chosen = sorted(eligible, key=lambda item: (-item[0], item[1]))[:SELECTED_BITS]
    return sorted(index for _, index in chosen)


def _validate_indices(indices: list[int]) -> None:
    if len(indices) != SELECTED_BITS:
        raise ValueError(f"selection mask must contain {SELECTED_BITS} positions")
    if indices != sorted(indices) or len(set(indices)) != SELECTED_BITS:
        raise ValueError("selection positions must be unique and increasing")
    if indices[0] < 0 or indices[-1] >= CANDIDATE_BITS:
        raise ValueError("selection position outside the 1023-comparison schedule")


def fe_gen(raw_reads: list[list[int]], margins: list[float]) -> tuple[bytes, dict]:
    """Enroll one response and return ``(K_PUF, public_helper_data)``."""
    response = _majority_bits(raw_reads)
    indices = select_top950(margins)
    selected = _bits_to_int([response[index] for index in indices])

    random_message = secrets.randbits(bch950.SHORT_K)
    codeword = bch950.encode(random_message)
    code_offset = selected ^ codeword
    toeplitz_seed = toeplitz_extractor.generate_seed()
    k_puf = toeplitz_extractor.extract_int(selected, toeplitz_seed)

    helper = {
        "version": HELPER_VERSION,
        "candidate_bits": CANDIDATE_BITS,
        "selected_bits": SELECTED_BITS,
        "margin_threshold_ppm": int(MARGIN_THRESHOLD * 1_000_000),
        "reads_per_challenge": READS_PER_CHALLENGE,
        "bch_n": bch950.SHORT_N,
        "bch_k": bch950.SHORT_K,
        "bch_t": bch950.T,
        "selection_indices": indices,
        "code_offset": _pack_fixed(code_offset, SELECTED_BITS),
        "toeplitz_seed": toeplitz_seed,
    }
    return k_puf, helper


def _validate_helper(helper: dict) -> list[int]:
    required = {
        "version", "candidate_bits", "selected_bits", "margin_threshold_ppm",
        "reads_per_challenge", "bch_n", "bch_k", "bch_t",
        "selection_indices", "code_offset", "toeplitz_seed",
    }
    if set(helper) != required:
        raise ValueError("helper data has missing or unknown fields")
    expected = {
        "version": HELPER_VERSION,
        "candidate_bits": CANDIDATE_BITS,
        "selected_bits": SELECTED_BITS,
        "margin_threshold_ppm": int(MARGIN_THRESHOLD * 1_000_000),
        "reads_per_challenge": READS_PER_CHALLENGE,
        "bch_n": bch950.SHORT_N,
        "bch_k": bch950.SHORT_K,
        "bch_t": bch950.T,
    }
    for field, value in expected.items():
        if helper[field] != value:
            raise ValueError(f"unsupported helper-data parameter: {field}")
    indices = list(helper["selection_indices"])
    _validate_indices(indices)
    _unpack_fixed(helper["code_offset"], SELECTED_BITS)
    if len(helper["toeplitz_seed"]) != toeplitz_extractor.SEED_BYTES:
        raise ValueError("invalid Toeplitz seed length")
    return indices


def fe_rec(raw_reads_noisy: list[list[int]], helper: dict) -> bytes | None:
    """Reconstruct K_PUF, returning ``None`` on decoder failure."""
    try:
        indices = _validate_helper(helper)
        response = _majority_bits(raw_reads_noisy)
        selected_noisy = _bits_to_int([response[index] for index in indices])
        code_offset = _unpack_fixed(helper["code_offset"], SELECTED_BITS)
        received_codeword = selected_noisy ^ code_offset
        decoded = bch950.decode(received_codeword)
        if decoded is None:
            return None
        _, corrected_codeword, _ = decoded
        enrolled_selected = corrected_codeword ^ code_offset
        return toeplitz_extractor.extract_int(
            enrolled_selected, helper["toeplitz_seed"]
        )
    except (TypeError, ValueError, KeyError):
        return None


def gen_from_seed(c_seed: bytes) -> tuple[bytes, dict]:
    """Software-emulator enrollment wrapper; not a physical PUF measurement."""
    challenges = challenge_schedule.challenge_schedule(c_seed)
    reads = puf_emulated.acquire_response_reads(challenges)
    margins = puf_emulated.enrollment_margins(challenges)
    return fe_gen(reads, margins)


def rec_from_seed(c_seed: bytes, helper: dict) -> bytes | None:
    challenges = challenge_schedule.challenge_schedule(c_seed)
    reads = puf_emulated.acquire_response_reads(challenges)
    return fe_rec(reads, helper)
