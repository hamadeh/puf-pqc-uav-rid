"""
interval_journal.py

The crash-consistent two-slot interval journal from Eq. (24) and
Algorithm 4's ReserveNext(k, j+1), plus the recovery rule described in
Table 11 ("select the checksum-valid slot with the highest generation
number; fail closed if neither slot validates").

New module, alongside the existing shared/*.py files (none of which
implement this journal today: uav_phase3_activate_and_broadcast.py
currently persists j_last by rewriting the whole uav_store_nv.json
file via protocol_common.write_message() after every interval, which
is not the crash-consistent pwrite+fdatasync+read-back journal Table
11 describes). This module is standalone and does not modify that
script; wiring it in is a separate decision for you to make.

ON-DISK LAYOUT, matching Table 11 exactly: one preallocated 8192-byte
file containing two alternating 4096-byte generation-numbered slots.
Each slot holds a small header (magic, format version, root identifier
k, generation number g, next-interval index j_next, checksum) and is
zero-padded out to 4096 bytes; the padding has no meaning and exists
purely so each slot starts on its own 4096-byte boundary, matching a
typical filesystem block size (relevant to the write's atomicity
properties, not just tidiness).

    offset 0     : slot 0 (4096 bytes)
    offset 4096  : slot 1 (4096 bytes)

Slot header (57 bytes, then zero padding):
    magic       4 bytes   b"RIDJ"
    version     1 byte    1
    root_id (k) 4 bytes   unsigned, big-endian
    generation  8 bytes   unsigned, big-endian (g_k)
    j_next      8 bytes   unsigned, big-endian (j_next^(k))
    checksum   32 bytes   H256("state" || g || k || j_next), Eq. (24)

CHECKSUM DOMAIN TAG NOTE: Table 5 lists "state" as the domain-separation
label for the interval-journal record checksum, but protocol_common.py
(the file both machines must keep byte-identical, per its own
docstring) does not currently define a TAG_STATE constant alongside its
other Table 5 labels. Rather than edit that shared file without asking,
the tag is defined locally below (_TAG_STATE = b"state"); if you decide
to wire this journal into the live protocol, moving that constant into
protocol_common.py alongside the others would be the natural cleanup.

DURABILITY: reserve_next() below performs exactly the sequence Table 11
specifies -- pwrite() the inactive slot, fdatasync(), check the return
status, read the slot back, and verify its generation number and
checksum -- and returns success only if every step validates. It does
not touch the previously-active slot. os.fdatasync is POSIX/Linux
(available on the Raspberry Pi's ext4 target); on platforms without it
(e.g. macOS, used only for local development smoke-testing of this
module, never for real Table 13 numbers) it falls back to os.fsync
with a printed warning, since Table 13's real results must come from
the Pi's actual fdatasync() path per the paper's own methodology note
that "completion of a buffered file-system write alone does not
satisfy" the durability assumption.
"""

import os
import struct

import crypto_primitives as cp

MAGIC = b"RIDJ"
VERSION = 1
SLOT_BYTES = 4096
NUM_SLOTS = 2
JOURNAL_BYTES = SLOT_BYTES * NUM_SLOTS
HEADER_STRUCT = struct.Struct(">4sBIQQ32s")  # magic, version, k, g, j_next, checksum
assert HEADER_STRUCT.size <= SLOT_BYTES

_TAG_STATE = b"state"  # see module docstring: Table 5 label, not yet in protocol_common.py


def _checksum(generation: int, k: int, j_next: int) -> bytes:
    return cp.hash_bytes(
        _TAG_STATE + generation.to_bytes(8, "big") + k.to_bytes(4, "big") +
        j_next.to_bytes(8, "big")
    )


def build_slot_bytes(k: int, generation: int, j_next: int) -> bytes:
    """Serializes one full SLOT_BYTES-byte slot record."""
    chk = _checksum(generation, k, j_next)
    header = HEADER_STRUCT.pack(MAGIC, VERSION, k, generation, j_next, chk)
    return header + b"\x00" * (SLOT_BYTES - len(header))


def parse_slot_bytes(raw: bytes) -> dict | None:
    """
    Parses SLOT_BYTES bytes read from one slot. Returns
    {"k", "generation", "j_next"} if the magic, version, and checksum
    all validate, else None (an invalid slot -- freshly preallocated,
    torn write, or corruption).
    """
    if len(raw) < HEADER_STRUCT.size:
        return None
    magic, version, k, generation, j_next, chk = HEADER_STRUCT.unpack(raw[:HEADER_STRUCT.size])
    if magic != MAGIC or version != VERSION:
        return None
    if chk != _checksum(generation, k, j_next):
        return None
    return {"k": k, "generation": generation, "j_next": j_next}


def _fdatasync(fd: int) -> None:
    if hasattr(os, "fdatasync"):
        os.fdatasync(fd)
    else:
        print("WARNING: os.fdatasync unavailable on this platform, falling back "
              "to os.fsync. Real Table 13 numbers must be collected on the "
              "Raspberry Pi, where os.fdatasync is available.")
        os.fsync(fd)


def create(path: str, k: int) -> None:
    """
    Preallocates the 8192-byte journal file and writes the initial
    state from Algorithm 1 step 28: J_{k,0} <- {g=0, k, j_next=1,
    checksum}, J_{k,1} left unwritten (invalid: reads back as None).
    """
    slot0 = build_slot_bytes(k, generation=0, j_next=1)
    slot1 = b"\x00" * SLOT_BYTES
    with open(path, "wb") as f:
        f.write(slot0 + slot1)
        f.flush()
        _fdatasync(f.fileno())


def read_slot(path_or_fd, slot_index: int) -> dict | None:
    """Reads and validates one slot (0 or 1). path_or_fd may be a path or an open fd."""
    offset = slot_index * SLOT_BYTES
    if isinstance(path_or_fd, int):
        raw = os.pread(path_or_fd, SLOT_BYTES, offset)
    else:
        with open(path_or_fd, "rb") as f:
            f.seek(offset)
            raw = f.read(SLOT_BYTES)
    return parse_slot_bytes(raw)


def recover(path: str) -> tuple[int, dict] | None:
    """
    The recovery rule: read both slots independently, select the
    checksum-valid slot with the highest generation number. Returns
    (slot_index, record) for the winner, or None if neither slot
    validates (fail closed).
    """
    candidates = []
    for slot_index in (0, 1):
        record = read_slot(path, slot_index)
        if record is not None:
            candidates.append((slot_index, record))
    if not candidates:
        return None
    return max(candidates, key=lambda sc: sc[1]["generation"])


def write_slot_raw(fd: int, slot_index: int, data: bytes) -> None:
    """
    Low-level pwrite of exactly `data` (may be shorter than SLOT_BYTES,
    e.g. to simulate a torn write) to the given slot's offset. Used by
    reserve_next() for the normal path and directly by the crash-
    recovery fault-injection harness to construct interrupted states.
    """
    os.pwrite(fd, data, slot_index * SLOT_BYTES)


def reserve_next(path: str, k: int, new_j_next: int) -> bool:
    """
    ReserveNext(k, new_j_next), Algorithm 4's durable reservation
    step, uninterrupted (no fault injection). Writes the inactive
    slot, fdatasyncs, and validates the read-back before returning.
    Returns True only if every step succeeded and the new value is
    confirmed durable; False (fail-safe: caller must not transmit)
    otherwise.
    """
    current = recover(path)
    if current is None:
        return False
    active_slot, active_record = current
    inactive_slot = 1 - active_slot
    new_generation = active_record["generation"] + 1

    new_bytes = build_slot_bytes(k, new_generation, new_j_next)

    fd = os.open(path, os.O_RDWR)
    try:
        write_slot_raw(fd, inactive_slot, new_bytes)
        _fdatasync(fd)
        readback = read_slot(fd, inactive_slot)
    finally:
        os.close(fd)

    if readback is None:
        return False
    if readback["generation"] != new_generation or readback["j_next"] != new_j_next:
        return False
    return True
