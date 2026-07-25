"""
puf_emulated.py

SOFTWARE-EMULATED PUF. This is NOT a real RO-PUF, and its bit-error
behavior is NOT a modeled prediction of one -- that co-simulation
boundary belongs to LTspice (see the LTspice code/ directory and Task
C's entropy-characterization pipeline), never to this emulator. This
module exists purely so Phase 2/3/4's majority-voting and BCH-
correction code paths have something to run against on a machine with
no real RO-PUF attached.

WHAT CHANGED FROM THE EARLIER VERSION: that version returned one
persisted value per challenge with zero noise, which meant
MajorityPUF's majority vote and FE.Rec's error correction were
structurally unreachable code (every read agreed with every other
read, always). This version separates two things that a real
comparator-based PUF also separates: a STABLE per-challenge ground
truth (which oscillator is faster for a given challenge -- a fixed
property of the emulated "device", persisted the same way the old
single-value-per-challenge store was) from INDEPENDENT per-read noise
(comparator jitter -- fresh randomness every time a read is taken, not
persisted, because a real comparator doesn't remember its last noise
draw either). Nine independent noisy reads of the same stable ground
truth is exactly MajorityPUF's input (Eq. 3).

_DEFAULT_FLIP_PROB is a testing knob, not a modeled bit-error rate; do
not read it as a PUF reliability number. SIZING WARNING, found the hard
way while wiring this up: t must be sized well above the *expected*
post-majority error count, not just above it, because binomial
variance regularly pushes the realized count past the mean. At
flip_prob=0.15 the post-9-read-majority per-bit error rate is
~0.0056, an expected ~5.8 errors over 1023 bits against BCH's t=8
budget -- comfortably under 8 on average, but with enough spread that
FE.Rec failed on the very first reconstruction attempt tried during
this rewrite. flip_prob=0.05 (the current default) drops the expected
count to ~0.03 errors, safely inside t=8's budget, while still being
nonzero so majority voting and BCH correction are genuinely exercised
rather than structurally unreachable. Raise it only with the above
math re-checked against BCH(1023,943,17)'s actual t=8 capacity over the
936-bit region puf_pipeline_1023.py can protect (see that module's
capacity caveat), not by intuition.

OPERATIONAL WARNING, unchanged from before: if you delete
.puf_store.json without also re-running Phase 2 enrollment from
scratch, any later Phase 3/4 script will get DIFFERENT ground-truth
ideas for the same challenges than the ones enrollment used, and
fuzzy_extractor.fe_rec() will fail to reconstruct S1/S2. The failure
looks like a fuzzy-extractor bug but isn't one, it's a stale-state
problem. If you ever see FE.Rec failing unexpectedly, check whether
.puf_store.json and uav_store_nv.json actually came from the same
enrollment run before looking anywhere else.
"""

import json
import hashlib
import os
import secrets

_STORE_PATH = os.path.join(os.path.dirname(__file__), ".puf_store.json")

_DEFAULT_FLIP_PROB = 0.05  # emulator testing knob; see module docstring

# In-memory mirror of the on-disk store, lazily loaded once per process.
# PERFORMANCE NOTE, found the hard way: an earlier version of true_bit()
# called _load_store() (a full file read + JSON parse) on every single
# call, with no caching. That's fine for the old one-call-per-challenge
# design, but acquire_response_reads() now calls it up to
# NUM_CHALLENGES * READS_PER_CHALLENGE = 1023 * 9 = 9207 times per
# acquisition -- reloading and re-parsing the whole (growing) store file
# 9207 times, which made a single evaluate_protocol.py run take minutes
# instead of the seconds its own docstring promises. This module-level
# cache is loaded from disk once per process (via _ensure_cache_loaded())
# and saved back only when a genuinely new challenge is added, not on
# every read. Cross-process persistence (the actual property that
# matters, see the OPERATIONAL WARNING below) is unaffected: each
# separate script invocation (Phase 2, then Phase 3, then Phase 4) still
# loads the full persisted store fresh at process start.
_cache = None


def _ensure_cache_loaded() -> None:
    global _cache
    if _cache is not None:
        return
    if os.path.exists(_STORE_PATH):
        with open(_STORE_PATH, "r") as f:
            _cache = json.load(f)
    else:
        _cache = {}


def _save_store() -> None:
    with open(_STORE_PATH, "w") as f:
        json.dump(_cache, f)


def true_bit(challenge: int) -> int:
    """
    The emulated device's stable, persisted ground-truth comparator
    outcome for this challenge -- analogous to "which oscillator in the
    pair is faster", a fixed property of one emulated device, not
    something that changes between enrollment and later reconstruction.
    """
    _ensure_cache_loaded()
    key = str(challenge)
    if key not in _cache:
        _cache[key] = secrets.randbelow(2)
        _save_store()
    return _cache[key]


def noisy_read(challenge: int, flip_prob: float = _DEFAULT_FLIP_PROB) -> int:
    """
    One independent noisy comparator read: the persisted true bit,
    flipped with probability flip_prob. Not persisted -- every call is
    a fresh draw, matching how repeated real comparator reads of a
    fixed physical quantity each carry independent thermal/jitter noise.
    """
    bit = true_bit(challenge)
    if secrets.randbelow(10 ** 6) < int(flip_prob * 10 ** 6):
        bit ^= 1
    return bit


def acquire_response_reads(challenges: list, reads_per_challenge: int = 9,
                            flip_prob: float = _DEFAULT_FLIP_PROB) -> list:
    """
    reads[i] = a list of reads_per_challenge independent noisy reads of
    challenges[i], the direct input to majority_vote.majority_vote().
    Call once per FE.Gen (enrollment) or FE.Rec (reconstruction)
    attempt; a fresh call draws fresh noise, as it should. Batches the
    ground-truth lookup/persistence through the in-memory cache (see
    above) instead of one disk round trip per read.
    """
    _ensure_cache_loaded()
    flip_threshold = int(flip_prob * 10 ** 6)

    new_challenges = False
    reads = []
    for c in challenges:
        key = str(c)
        if key not in _cache:
            _cache[key] = secrets.randbelow(2)
            new_challenges = True
        bit = _cache[key]
        reads.append([
            bit ^ (1 if secrets.randbelow(10 ** 6) < flip_threshold else 0)
            for _ in range(reads_per_challenge)
        ])

    if new_challenges:
        _save_store()
    return reads


def enrollment_margins(challenges: list) -> list[float]:
    """
    Deterministic synthetic normalized margins for software-path testing.

    These values are not LTspice results and are not physical measurements.
    They merely make the emulator expose the margin-bearing enrollment API
    required by the top-950 selection rule.  Every generated margin is above
    the 0.5% enrollment threshold; ordering is deterministic per challenge.
    """
    margins = []
    for challenge in challenges:
        digest = hashlib.sha256(
            b"PUF-EMULATED-MARGIN-v1" + int(challenge).to_bytes(2, "big")
        ).digest()
        fraction = int.from_bytes(digest[:8], "big") / (1 << 64)
        margins.append(0.006 + 0.044 * fraction)
    return margins


def reset_store() -> None:
    """Erase all persisted emulated-PUF state (start a 'fresh device')."""
    global _cache
    _cache = None
    if os.path.exists(_STORE_PATH):
        os.remove(_STORE_PATH)
