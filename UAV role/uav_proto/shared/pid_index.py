"""
pid_index.py

Sorted pseudonym index used by the final Profile-P wire format.

The verifier sends only AuthRef (the observed 16-byte PID), so the UAV
must recover the corresponding interval index j.  Building this index
during root activation keeps Phase 4 lookup at O(log n) instead of
scanning every active pseudonym.

The index is a list of (pid, j) tuples sorted lexicographically by pid.
PIDs are required to be unique within a root; a duplicate is treated as
an activation failure rather than silently choosing one interval.
"""

from bisect import bisect_left


def build_pid_index(pids: list[bytes]) -> list[tuple[bytes, int]]:
    """Build and validate the sorted PIDIndex for one active root."""
    index = sorted((pid, j) for j, pid in enumerate(pids))
    for left, right in zip(index, index[1:]):
        if left[0] == right[0]:
            raise ValueError("duplicate PID in active root")
    return index


def indexed_find_j(index: list[tuple[bytes, int]], target_pid: bytes) -> int:
    """Return the interval index for target_pid, or -1 when absent."""
    position = bisect_left(index, (target_pid, -1))
    if position < len(index) and index[position][0] == target_pid:
        return index[position][1]
    return -1
