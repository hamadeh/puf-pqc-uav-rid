"""
challenge_schedule.py

ChallengeSchedule(CSeed, q=1023), Algorithm 1 line 1: a deterministic,
ordered list of q distinct 12-bit challenges derived from a public seed
CSeed. Nothing in this codebase generated a real challenge schedule
before this file; challenges were ad hoc random tokens picked fresh at
enrollment time rather than a reproducible schedule any later
reconstruction (Phase 3 activation, Phase 4 authentication, or a
verifier's HSpice-side analysis) could regenerate from CSeed alone.

UAV-side only: nothing on the TA/verifier side ever needs to
regenerate a challenge schedule, so this module is not duplicated into
the TA Verifier role tree the way protocol_common.py/merkle.py are.
"""

import hashlib

NUM_CHALLENGES = 1023
CHALLENGE_BITS = 12
_CHALLENGE_MASK = (1 << CHALLENGE_BITS) - 1  # 0xFFF


def challenge_schedule(c_seed: bytes, q: int = NUM_CHALLENGES) -> list:
    """
    Deterministic list of q distinct 12-bit challenge values (0..4095),
    derived from c_seed via SHAKE256 rejection sampling. Same c_seed
    always returns the same ordered schedule; the ordering itself is
    part of the schedule (challenge index j corresponds to
    schedule[j]).
    """
    if q > (1 << CHALLENGE_BITS):
        raise ValueError(f"q={q} exceeds the {1 << CHALLENGE_BITS} possible 12-bit challenges")

    seen = set()
    schedule = []
    counter = 0
    while len(schedule) < q:
        block = hashlib.shake_256(c_seed + counter.to_bytes(8, "big")).digest(2)
        value = int.from_bytes(block, "big") & _CHALLENGE_MASK
        counter += 1
        if value in seen:
            continue
        seen.add(value)
        schedule.append(value)
    return schedule
