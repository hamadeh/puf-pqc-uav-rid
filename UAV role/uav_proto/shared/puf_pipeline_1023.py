"""
puf_pipeline_1023.py

The paper-scale (1023-bit, BCH(1023,943,17)-class) majority-vote / BCH /
Toeplitz pipeline: MajorityPUF -> FE.Gen/FE.Rec -> Ext_rho, Eq. (3)-(5).

Originally built standalone for Table 17's benchmark row; now also the
implementation fuzzy_extractor.py delegates to for the live protocol
(Phase 2/3/4), so this module is production infrastructure, not
benchmark-only. Moved here from pi_side/ for that reason. It has no
opinion on WHERE its raw_reads argument comes from: benchmark_table17.py
feeds it synthetic same-shaped data (see that script's docstring for why
that is safe for a pure timing benchmark and would not be for an entropy
claim); fuzzy_extractor.py feeds it puf_emulated.acquire_response_reads()
output for the live protocol.

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

TAIL-ZEROING, a correctness fix (not present in the first version of
this module): the 87 bits beyond the BCH-protected message are never
error-corrected, so they must never be allowed to vary between
enrollment and reconstruction, or Ext_rho's output would silently stop
being deterministic under any noise landing in that region -- exactly
the noisy-reconstruction case a fuzzy extractor exists to handle.
Passing the tail through as-read (what an earlier version of this
module did) breaks that guarantee: it happened not to be caught by
Task A's own tests only because those tests confined injected errors
to the protected region on purpose. Both fe_gen_1023 and fe_rec_1023
therefore zero the unprotected tail before Toeplitz extraction rather
than forwarding either party's raw read of it, so the Toeplitz input
is always the fixed value {corrected 936-bit message, 87 zero bits,
zero pad bit} -- deterministic regardless of tail noise, at the cost
of those 87 bits never contributing extractable entropy. That is a
deliberate, disclosed trade against Table 11/14's literal "full
1023-bit response vector" framing, forced by bchlib's byte-oriented
capacity shortfall documented above; Task C's real entropy
characterization must account for only ~936 bits actually being
usable this way if it ever needs to reconcile against this module's
behavior.
"""

import bchlib

import majority_vote
import toeplitz_extractor

_T = 8
_M = 10  # bch.n = 2**10 - 1 = 1023, matching BCH(1023,943,17)'s codeword length

BCH_MESSAGE_BYTES = 117  # 936 bits; see module docstring capacity caveat
RESPONSE_BYTES = majority_vote.RESPONSE_BYTES  # 128 bytes (1023 bits + 1 pad bit)


def _make_bch() -> "bchlib.BCH":
    return bchlib.BCH(t=_T, m=_M)


def _zero_tail(message: bytes) -> bytes:
    """message (BCH_MESSAGE_BYTES) + a fixed zero tail, padded to RESPONSE_BYTES."""
    return message + b"\x00" * (RESPONSE_BYTES - BCH_MESSAGE_BYTES)


def fe_gen_1023(raw_reads: list[list[int]]) -> tuple[bytes, bytes, bytes]:
    """
    Enrollment-time path: majority vote -> BCH encode -> Toeplitz extract.

    Returns (K_PUF, bch_ecc, toeplitz_seed). bch_ecc and toeplitz_seed
    together are the public helper data HD = (s, rho) of Eq. (4);
    K_PUF is the 256-bit extracted secret, never stored. See the module
    docstring's TAIL-ZEROING note for why Toeplitz extraction runs over
    {message, zero tail}, not the raw majority-voted tail.
    """
    R = majority_vote.majority_vote(raw_reads)
    bch = _make_bch()
    message = bytearray(R[:BCH_MESSAGE_BYTES])
    ecc = bch.encode(bytes(message))
    seed = toeplitz_extractor.generate_seed()
    k_puf = toeplitz_extractor.extract(_zero_tail(bytes(message)), seed)
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

    return toeplitz_extractor.extract(_zero_tail(bytes(message)), toeplitz_seed)
