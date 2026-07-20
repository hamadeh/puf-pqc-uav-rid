"""
fuzzy_extractor.py

FE.Gen / FE.Rec, Eq. (4)-(5): ChallengeSchedule -> MajorityPUF(9 reads)
-> BCH(1023,943,17) secure sketch -> seeded 256-bit Toeplitz extraction.
Delegates to puf_pipeline_1023.py (the majority-vote/BCH/Toeplitz
pipeline originally built for the Table 17 benchmark, now shared
production infrastructure), majority_vote.py, and
toeplitz_extractor.py, rather than reimplementing that pipeline here.

WHAT CHANGED FROM THE EARLIER VERSION: that version worked over a
64-byte raw response from a single puf_emulated.puf_response() call,
using BCH t=8/m=13 (a 8191-bit codeword sized for a 512-bit input) and
extracting the secret via a plain hash rather than a Toeplitz
extractor -- none of which matches the paper's actual construction (a
1023-bit majority-voted RO-PUF response, BCH(1023,943,17), and the
seeded 2-universal Toeplitz extractor of Eq. 4-5). This version fixes
that by using the real pipeline for both PUF channels (this codebase
keeps the dual-challenge design: one independent challenge schedule and
FE.Gen/FE.Rec call for S1's channel, another for S2's -- see
uav_phase2_enroll_request.py -- rather than the paper's single-K_PUF +
SHAKE256 split; both channels individually now run the paper-exact
per-challenge pipeline).

HELPER DATA FORMAT: HD = bch_ecc (10 bytes) || toeplitz_seed (160
bytes) = 170 bytes total, packed as one blob for API compatibility
with callers that store a single HD value (Store_NV). This matches the
paper's own stated total exactly: Table 16 states "170 bytes of helper
data."
"""

import challenge_schedule
import puf_emulated
import puf_pipeline_1023 as _pipeline

_ECC_BYTES = 10  # bchlib(t=8, m=10)'s ecc_bytes; see puf_pipeline_1023.py


def fe_gen(raw_reads: list) -> tuple:
    """
    FE.Gen(R) -> (secret, helper_data), Eq. (4).

    raw_reads: NUM_CHALLENGES x READS_PER_CHALLENGE noisy comparator
    reads (majority_vote.majority_vote()'s input shape), typically from
    puf_emulated.acquire_response_reads(). See gen_from_seed() below for
    a higher-level entry point that also handles challenge-schedule
    generation and PUF acquisition.
    """
    k_puf, ecc, toeplitz_seed = _pipeline.fe_gen_1023(raw_reads)
    helper_data = ecc + toeplitz_seed
    return k_puf, helper_data


def fe_rec(raw_reads_noisy: list, helper_data: bytes):
    """
    FE.Rec(R', helper_data) -> secret, or None if correction fails
    (more than t=8 bit errors in the BCH-protected message), Eq. (5).
    """
    ecc = helper_data[:_ECC_BYTES]
    toeplitz_seed = helper_data[_ECC_BYTES:]
    return _pipeline.fe_rec_1023(raw_reads_noisy, ecc, toeplitz_seed)


def gen_from_seed(c_seed: bytes) -> tuple:
    """
    Convenience wrapper for enrollment: ChallengeSchedule(c_seed) ->
    acquire 9 reads/challenge -> FE.Gen. Returns (secret, helper_data).
    """
    challenges = challenge_schedule.challenge_schedule(c_seed)
    reads = puf_emulated.acquire_response_reads(challenges)
    return fe_gen(reads)


def rec_from_seed(c_seed: bytes, helper_data: bytes):
    """
    Convenience wrapper for reconstruction (Phase 3 activation, Phase 4
    authentication): regenerates the SAME challenge schedule from
    c_seed (must be the identical seed used at enrollment), acquires a
    fresh set of 9 noisy reads per challenge, and runs FE.Rec. Returns
    the secret, or None if correction fails.
    """
    challenges = challenge_schedule.challenge_schedule(c_seed)
    reads = puf_emulated.acquire_response_reads(challenges)
    return fe_rec(reads, helper_data)
