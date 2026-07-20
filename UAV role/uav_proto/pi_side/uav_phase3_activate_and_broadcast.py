"""
uav_phase3_activate_and_broadcast.py

Runs on: the Pi 5 (UAV role, D_i). Only the UAV. This phase involves no
TA and no verifier, by design, that's the whole point of Phase 3 in your
protocol (see the "no TA contact" note in your own overview figure).

Implements: Algorithm 3 (Pre-Flight Root Activation), and Algorithm 4
(Crash-Consistent Pseudonym Reservation and Broadcast).

BEFORE RUNNING: this reads uav_store_nv.json (from uav_phase2_enroll_
finalize.py) and this root's interval_journal_k<k>.bin (from the same
script; Algorithm 1 step 28).

Produces:
  interval_journal_k<k>.bin (updated)
      ReserveNext(k, j+1) durably commits the next interval index
      BEFORE the corresponding packet is transmitted (Algorithm 4 step
      8), via a real pwrite()+fdatasync()+read-back-validate cycle
      (interval_journal.py), not by rewriting the whole
      uav_store_nv.json file every interval the way this script used
      to. That whole-file rewrite was not the crash-consistent
      mechanism Table 11 describes; this is.

  out/broadcast_log.jsonl
      One JSON line per transmitted RIDMsg_{k,j}. This is standing in
      for the actual Bluetooth/Wi-Fi broadcast, there's no radio
      involved. Appended to, not overwritten.

ALIGNED WITH THE PAPER: PID/leaf construction now includes FlightCtx_k
(Algorithm 1 line 17) and uses merkle.leaf_hash() (H384/TupleHash, Eq.
13), matching what uav_phase2_enroll_request.py now builds -- a root
enrolled under the old construction will not reactivate correctly
under this version, and vice versa; re-enroll after this change.
Response acquisition for S2 reconstruction now runs the real
ChallengeSchedule -> MajorityPUF -> FE.Rec pipeline via
fuzzy_extractor.rec_from_seed(), not a single noiseless
puf_response() call.
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
sys.path.insert(0, os.path.dirname(__file__))

import protocol_common as pc
import crypto_primitives as cp
import merkle
import fuzzy_extractor
import interval_journal as ij
import pid_index

IN_DIR = os.path.join(os.path.dirname(__file__), "in")
OUT_DIR = os.path.join(os.path.dirname(__file__), "out")


def select_root(store_nv: dict, n: int):
    """Pick the first root whose journal reports unused intervals remaining (j_next <= n)."""
    for root in store_nv["roots"]:
        journal_path = ij.journal_path_for_root(OUT_DIR, root["k"])
        recovered = ij.recover(journal_path)
        if recovered is None:
            print(f"  WARNING: root k={root['k']} journal recovery failed "
                  f"(both slots invalid), skipping this root.")
            continue
        _, record = recovered
        if record["j_next"] <= n:
            return root, journal_path, record["j_next"]
    return None, None, None


def synthetic_telemetry(j: int) -> dict:
    """
    Placeholder telemetry, NOT real GPS/flight-controller data. There's no
    real flight hardware here; this exists only so RIDMsg has the fields
    your protocol's message format specifies.
    """
    return {
        "loc": {"lat": 40.0 + j * 0.0001, "lon": -75.0 + j * 0.0001},
        "alt": 50.0,
        "vel": 5.0,
        "status": "airborne",
    }


def main():
    store_path = os.path.join(OUT_DIR, "uav_store_nv.json")
    if not os.path.exists(store_path):
        print(f"ERROR: {store_path} not found. Run Phase 2 enrollment first.")
        sys.exit(1)

    store_nv = pc.read_message(store_path)

    print("Phase 3: Pre-Flight Root Activation and Remote ID Broadcast")

    if not store_nv["roots"]:
        print("ERROR: no roots in Store_D_i^NV. Enrollment did not complete.")
        sys.exit(1)
    n = store_nv["roots"][0]["flight_ctx"]["n"]

    root, journal_path, j_next = select_root(store_nv, n)
    if root is None:
        print("Root exhausted: no root with unused intervals remains.")
        print("Select another authorized record or trigger renewal (Phase 2).")
        sys.exit(1)

    k = root["k"]
    print(f"Activating root k={k} (j_next={j_next}, n={n})")

    # --- Activation (Algorithm 3) ---
    S2 = fuzzy_extractor.rec_from_seed(store_nv["c_seed2"], store_nv["hd2"])
    if S2 is None:
        print("ERROR: FE.Rec failed to reconstruct S2. Cannot activate this root.")
        sys.exit(1)

    seed_k = cp.kdf(S2, root["root_nonce"], k.to_bytes(4, "big"), pc.TAG_MERKLE_ROOT)
    flight_ctx_bytes = pc.canonical_json_bytes(root["flight_ctx"])

    leaves = []
    pids = []
    for j in range(n):
        j_bytes = j.to_bytes(4, "big")
        x_kj = cp.kdf(seed_k, j_bytes, pc.TAG_INTERVAL_SECRET)
        pid_kj = cp.hash_bytes(
            pc.TAG_RID + x_kj + j_bytes + root["root_nonce"] + flight_ctx_bytes
        )[:16]
        leaf = merkle.leaf_hash(pid_kj, j, root["root_nonce"], flight_ctx_bytes)
        leaves.append(leaf)
        pids.append(pid_kj)

    levels = merkle.build_tree(leaves)
    recomputed_root = merkle.root(levels)

    if recomputed_root != root["mr_k"]:
        print("Root check FAILED: recomputed root does not match MR_i^(k).")
        print("Rejecting this root, nonvolatile storage may be corrupted or tampered.")
        sys.exit(1)

    print(f"Root check passed: recomputed root matches MR_i^(k) = {recomputed_root.hex()[:16]}...")

    # ActiveState_k lives only here, in memory, for the life of this script.
    # PIDIndex is part of activation under the final Profile-P wire format:
    # Phase 4 receives only an observed PID and uses this sorted index to
    # recover j in O(log n). Merkle paths are extracted from `levels` on
    # demand instead of precomputing n separate paths.
    active_state = {
        "pids": pids,
        "levels": levels,
        "pid_index": pid_index.build_pid_index(pids),
    }
    del S2, seed_k  # best-effort; see README on Python's lack of secure erasure

    if j_next > n:
        print("Root exhausted immediately (j_next already past n).")
        sys.exit(1)

    print(f"Activation complete. Broadcasting will resume from interval j={j_next}.")

    # --- Broadcast loop (Algorithm 4) ---
    delta_t = root["flight_ctx"]["delta_t"]
    log_path = os.path.join(OUT_DIR, "broadcast_log.jsonl")
    os.makedirs(OUT_DIR, exist_ok=True)

    t_activation = time.time()
    j = j_next

    print(f"Starting broadcast loop (interval={delta_t}s, up to j={n})."
          f" Ctrl+C to stop early; the journal durably tracks progress"
          f" after every interval, so a restart resumes correctly on its own.")

    try:
        while j <= n:
            elapsed = time.time() - t_activation
            expected_j = j_next + int(elapsed // delta_t)
            if expected_j > j:
                j = expected_j
                if j > n:
                    break

            # Algorithm 4 step 8: reserve-before-use. A crash between this
            # durable commit and the transmission below consumes interval j
            # without broadcasting it (a "skipped index", not a failure).
            if not ij.reserve_next(journal_path, k, j + 1):
                print(f"  ReserveNext(k={k}, j+1={j + 1}) FAILED: suppressing "
                      f"transmission, entering fail-safe state.")
                break

            pid_hex = active_state["pids"][j - 1].hex()
            telem = synthetic_telemetry(j)
            rid_msg = {
                "k": k,
                "j": j,
                "pid": pid_hex,
                "ts": time.time(),
                **telem,
            }

            with open(log_path, "a") as f:
                f.write(json.dumps(rid_msg) + "\n")

            print(f"  [j={j}/{n}] reserved + broadcast PID={pid_hex[:16]}...")

            j += 1
            time.sleep(delta_t)

    except KeyboardInterrupt:
        recovered = ij.recover(journal_path)
        resumed_from = recovered[1]["j_next"] if recovered else "?"
        print(f"\nStopped early. Journal durably at j_next={resumed_from}; "
              f"rerunning this script will resume from there.")

    print(f"\nBroadcast log: {log_path}")
    print(f"Journal: {journal_path}")


if __name__ == "__main__":
    main()
