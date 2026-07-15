"""
crash_recovery_harness.py

The Table 13 crash-recovery validation harness. Forces a power-loss-
equivalent interruption at the four points Section V-D and Table 11
describe, restarts (simulated by discarding all in-process state and
re-reading the journal file cold), and checks the paper's stated
acceptance criteria.

Run ON THE RASPBERRY PI 5 for real numbers (os.fdatasync must be the
real Linux/ext4 syscall, not the macOS fallback interval_journal.py
warns about; see that module's docstring).

DISPOSABLE JOURNAL ONLY. This is destructive by construction (that's
the point: it deliberately corrupts on-disk state to test recovery).
Every trial creates a brand-new journal file under a fresh temporary
directory (tempfile.mkdtemp()) and never touches any path outside it.
There is currently no "live" interval journal anywhere in this
codebase (uav_phase3_activate_and_broadcast.py persists j_last through
protocol_common.write_message(), not through interval_journal.py; see
that module's docstring), so there is nothing this harness could
collide with today. If interval_journal.py is later wired into a real
Phase 3 rewrite, this harness's on-every-trial-fresh-tempdir design
means it still can never touch that live file.

WHAT "INTERRUPTION" MEANS HERE. A test harness cannot literally cut
power mid-syscall. Each of the four points is instead modeled by
directly constructing the exact on-disk byte state that interruption
would leave behind, then cold-starting recovery against it, which is
the standard technique for this kind of test and is what actually
exercises the recovery code path:

  1. Before the slot write: reserve_next() is never called for this
     round. The inactive slot is untouched; the active slot still
     reflects the previous, already-durable state.
  2. During the write: the inactive slot is pwritten with only the
     first `torn_len` bytes of the new record, where torn_len is drawn
     from [25, 56] -- always past the magic/version/root-id/generation/
     j_next fields (bytes 0-24, always fully committed) but always
     short of the full 32-byte checksum field that follows (bytes
     25-56, so at least one checksum byte is always missing). This
     range is deliberate, not arbitrary: generation and j_next are
     incremented by one each reservation, so consecutive values differ
     only in their low-order byte(s); a torn write that stops anywhere
     in [0, 24] can coincidentally leave those fields reading as the
     numerically-unchanged old value (a real but structurally
     coincidental outcome, not a meaningful "corruption" case), which
     would silently validate against the untouched old checksum and
     fail to exercise this interruption point at all. Restricting
     torn_len to always fully commit the header fields but never fully
     commit the checksum guarantees the stored checksum bytes are a
     new/old mix that will not, for a cryptographically-strong hash,
     coincidentally equal a validly recomputed checksum of the
     (now-committed) new generation/j_next -- reliably producing the
     "checksum fails to validate" case this interruption point is
     meant to test, while still modeling a genuine partial write rather
     than an artificially-forced corruption. No fdatasync is called.
  3. After fdatasync() returns but before transmission: a full,
     correct reserve_next() runs (matching Table 11's complete
     pwrite+fdatasync+read-back path), but the corresponding pseudonym
     is never added to the trial's transmitted set, modeling a crash
     between durable reservation and the first broadcast packet. The
     paper explicitly permits this: "such an event is counted as a
     skipped index rather than a recovery failure."
  4. Immediately after transmission: same full reserve_next(), and the
     pseudonym IS recorded as transmitted before the simulated crash.

ACCEPTANCE CRITERION (from Section V-D): zero reuse of a pseudonym
that had already been transmitted. Reuse is checked by interval index
rather than by re-hashing a pseudonym string, since in this
construction each index maps to exactly one pseudonym; index reuse and
pseudonym reuse are the same event here, and checking indices avoids
relying on incidental hash non-collision for the test's own soundness.

USAGE:
    python3 crash_recovery_harness.py
        250 trials per interruption point (1000 total), matching
        Table 13's need for "statistically meaningful counts".

    python3 crash_recovery_harness.py --trials-per-point 20
        Quick smoke test; writes to *_quicktest files.

OUTPUT:
    results_table13.csv        one row per interruption point
    results_table13_rows.tex   LaTeX rows for Table 13
"""

import sys
import os
import time
import tempfile
import shutil
import secrets
import csv
import argparse
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import interval_journal as ij

DEFAULT_TRIALS_PER_POINT = 250
ROOT_K = 0
WARMUP_STEPS = 3  # normal reserve+transmit cycles before injecting a fault
POST_RECOVERY_STEPS = 3  # continuation cycles after recovery, to probe for reuse

INTERRUPTION_POINTS = [
    "before_slot_write",
    "during_write",
    "after_fdatasync_before_transmission",
    "immediately_after_transmission",
]


def _new_journal(tmpdir: str) -> str:
    path = os.path.join(tmpdir, f"journal_{secrets.token_hex(8)}.bin")
    ij.create(path, k=ROOT_K)
    return path


def _reserve_and_transmit(path: str, j_target: int, transmitted_js: set) -> bool:
    """Normal, uninterrupted cycle: durably reserve j_target, then transmit it."""
    ok = ij.reserve_next(path, ROOT_K, j_target + 1)
    if not ok:
        return False
    transmitted_js.add(j_target)
    return True


def _slot_validity(path: str) -> tuple:
    """Returns (slot0_valid, slot1_valid) as bools."""
    return (ij.read_slot(path, 0) is not None, ij.read_slot(path, 1) is not None)


def run_trial(point: str, tmpdir: str) -> dict:
    """
    One full trial: fresh journal, warmup, inject the interruption at
    `point`, cold-recover, run continuation steps, report the metrics
    this trial contributes.
    """
    path = _new_journal(tmpdir)
    transmitted_js = set()

    # Warm up: a few normal cycles so the fault isn't always injected
    # against the pristine initial state.
    current = ij.recover(path)
    j = current[1]["j_next"]
    for _ in range(WARMUP_STEPS):
        _reserve_and_transmit(path, j, transmitted_js)
        current = ij.recover(path)
        j = current[1]["j_next"]

    j_target = j  # the interval this trial's fault targets
    unused_index_consumed = False

    if point == "before_slot_write":
        pass  # no write at all this round; journal state is unchanged

    elif point == "during_write":
        active_slot, active_record = ij.recover(path)
        inactive_slot = 1 - active_slot
        new_generation = active_record["generation"] + 1
        full_record = ij.build_slot_bytes(ROOT_K, new_generation, j_target + 1)
        checksum_field_start = ij.HEADER_STRUCT.size - 32  # byte 25: header fields end, checksum begins
        torn_len = checksum_field_start + secrets.randbelow(32)  # [25, 56]: full header, partial checksum
        fd = os.open(path, os.O_RDWR)
        try:
            ij.write_slot_raw(fd, inactive_slot, full_record[:torn_len])
            # deliberately no fdatasync: this is the "during the write" crash
        finally:
            os.close(fd)

    elif point == "after_fdatasync_before_transmission":
        ok = ij.reserve_next(path, ROOT_K, j_target + 1)
        if ok:
            unused_index_consumed = True
        # pseudonym for j_target is NOT added to transmitted_js: crash
        # happens before the first packet.

    elif point == "immediately_after_transmission":
        _reserve_and_transmit(path, j_target, transmitted_js)

    else:
        raise ValueError(point)

    # ---- cold restart: recovery ----
    t0 = time.perf_counter()
    recovered = ij.recover(path)
    t1 = time.perf_counter()
    recovery_time_ms = (t1 - t0) * 1000

    slot0_valid, slot1_valid = _slot_validity(path)
    invalid_count = (0 if slot0_valid else 1) + (0 if slot1_valid else 1)
    both_invalid = (recovered is None)

    reuse_detected = False
    if recovered is not None:
        recovered_j_next = recovered[1]["j_next"]
        # Reuse would mean recovery rewound j_next to or below an
        # already-transmitted index, so the next reservation could
        # hand out an index whose pseudonym was already broadcast.
        if transmitted_js and recovered_j_next <= max(transmitted_js):
            reuse_detected = True

        # Continue operating from the recovered state and confirm no
        # continuation step ever reproduces an already-transmitted index.
        jc = recovered_j_next
        for _ in range(POST_RECOVERY_STEPS):
            if jc in transmitted_js:
                reuse_detected = True
            ok = _reserve_and_transmit(path, jc, transmitted_js)
            if not ok:
                break
            current = ij.recover(path)
            jc = current[1]["j_next"]

    return {
        "invalid_single_slot": 1 if invalid_count == 1 else 0,
        "both_slots_invalid": 1 if both_invalid else 0,
        "pseudonym_reuse": 1 if reuse_detected else 0,
        "unused_index_consumed": 1 if unused_index_consumed else 0,
        "recovery_time_ms": recovery_time_ms,
    }


def run_point(point: str, trials: int) -> dict:
    tmpdir = tempfile.mkdtemp(prefix="ridjournal_crashtest_")
    try:
        invalid_single = 0
        both_invalid = 0
        reuse = 0
        unused_consumed = 0
        recovery_times = []

        for _ in range(trials):
            result = run_trial(point, tmpdir)
            invalid_single += result["invalid_single_slot"]
            both_invalid += result["both_slots_invalid"]
            reuse += result["pseudonym_reuse"]
            unused_consumed += result["unused_index_consumed"]
            recovery_times.append(result["recovery_time_ms"])

        return {
            "interruption_point": point,
            "forced_interruptions": trials,
            "invalid_single_slot_records": invalid_single,
            "both_slots_invalid": both_invalid,
            "pseudonym_reuse_count": reuse,
            "unused_indices_consumed": unused_consumed,
            "max_recovery_time_ms": round(max(recovery_times), 4),
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def print_table(rows: list):
    columns = ["interruption_point", "forced_interruptions", "invalid_single_slot_records",
               "both_slots_invalid", "pseudonym_reuse_count", "unused_indices_consumed",
               "max_recovery_time_ms"]
    widths = {c: max(len(c), max((len(str(r[c])) for r in rows), default=0)) for c in columns}
    print("  ".join(c.ljust(widths[c]) for c in columns))
    print("-" * (sum(widths.values()) + 2 * (len(columns) - 1)))
    for r in rows:
        print("  ".join(str(r[c]).ljust(widths[c]) for c in columns))


def write_latex_summary(rows: list, path: str):
    """
    Table 13 is metric-per-row, not interruption-point-per-row. Sum
    across the four interruption points for the metrics that are
    naturally additive (counts), and take the overall max for recovery
    time, matching how the paper's table is laid out.
    """
    total_interruptions = sum(r["forced_interruptions"] for r in rows)
    total_invalid_single = sum(r["invalid_single_slot_records"] for r in rows)
    total_both_invalid = sum(r["both_slots_invalid"] for r in rows)
    total_reuse = sum(r["pseudonym_reuse_count"] for r in rows)
    total_unused = sum(r["unused_indices_consumed"] for r in rows)
    overall_max_recovery = max(r["max_recovery_time_ms"] for r in rows)

    with open(path, "w") as f:
        f.write("% Generated by crash_recovery_harness.py\n")
        f.write("% Aggregated across all four interruption points "
                f"({', '.join(INTERRUPTION_POINTS)})\n")
        f.write(f"Forced interruptions & {total_interruptions} \\\\\n")
        f.write(f"Invalid single-slot records & {total_invalid_single} \\\\\n")
        f.write(f"Cases with both slots invalid & {total_both_invalid} \\\\\n")
        f.write(f"Previously transmitted pseudonyms reused & {total_reuse} \\\\\n")
        f.write(f"Unused indices consumed & {total_unused} \\\\\n")
        f.write(f"Maximum recovery time & {overall_max_recovery:.4f}\\,ms \\\\\n")


def main():
    parser = argparse.ArgumentParser(description="Table 13 crash-recovery validation harness.")
    parser.add_argument("--trials-per-point", type=int, default=DEFAULT_TRIALS_PER_POINT)
    args = parser.parse_args()
    trials = args.trials_per_point
    is_default_run = (trials == DEFAULT_TRIALS_PER_POINT)
    suffix = "" if is_default_run else "_quicktest"

    print("=" * 100)
    print("TABLE 13 CRASH-RECOVERY VALIDATION")
    print("=" * 100)
    print(f"  trials per interruption point: {trials} ({len(INTERRUPTION_POINTS)} points, "
          f"{trials * len(INTERRUPTION_POINTS)} total forced interruptions)")
    print(f"  os.fdatasync available: {hasattr(os, 'fdatasync')}"
          + ("" if hasattr(os, "fdatasync") else "  <-- run on the Pi for real Table 13 numbers"))
    print()

    rows = []
    for point in INTERRUPTION_POINTS:
        print(f"Running {point} ...")
        row = run_point(point, trials)
        rows.append(row)

    print()
    print_table(rows)

    if any(r["pseudonym_reuse_count"] > 0 for r in rows):
        print("\n*** ACCEPTANCE CRITERION FAILED: nonzero pseudonym reuse detected. ***")
        print("*** Do not report these numbers as passing Table 13's criterion. ***")
    else:
        print("\nAcceptance criterion met: zero previously-transmitted-pseudonym reuse "
              f"across all {trials * len(INTERRUPTION_POINTS)} forced interruptions.")

    csv_path = os.path.join(os.path.dirname(__file__), f"results_table13{suffix}.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "interruption_point", "forced_interruptions", "invalid_single_slot_records",
            "both_slots_invalid", "pseudonym_reuse_count", "unused_indices_consumed",
            "max_recovery_time_ms"])
        writer.writeheader()
        writer.writerows(rows)

    latex_path = os.path.join(os.path.dirname(__file__), f"results_table13_rows{suffix}.tex")
    write_latex_summary(rows, latex_path)

    print(f"\nWrote {csv_path}")
    print(f"Wrote {latex_path}")


if __name__ == "__main__":
    main()
