"""
uav_phase3_activate_and_broadcast.py

Runs on: the Pi 5 (UAV role, D_i). Only the UAV. This phase involves no
TA and no verifier, by design, that's the whole point of Phase 3 in your
protocol (see the "no TA contact" note in your own overview figure).

Implements: Algorithm 3 (Pre-Flight Root Activation and Remote ID
Broadcast), both halves: activation once before "takeoff", then the
per-interval broadcast loop.

BEFORE RUNNING: this reads uav_store_nv.json, which
uav_phase2_enroll_finalize.py produces. Run Phase 2 first if you haven't.

Produces:
  out/uav_store_nv.json (updated)
      j_last^(k) is written back after EVERY interval, not just at the
      end, on purpose. This is what makes the reboot-recovery property
      your paper describes actually true here: if this script is killed
      mid-loop, the next run picks up from the last persisted interval,
      not from zero.

  out/broadcast_log.jsonl
      One JSON line per transmitted RIDMsg_{k,j}. This is standing in for
      the actual Bluetooth/Wi-Fi broadcast, there's no radio involved.
      This file is what a Phase 4 verifier script will later read from to
      simulate "observing" a broadcast pseudonym. Appended to, not
      overwritten, so multiple runs accumulate a longer capture.

NOTE ON THE EMULATED PUF: puf_emulated.puf_response() is deterministic
per challenge with zero noise (see its docstring). That means FE.Rec's
error-correction path is never actually exercised by this script, S2
comes back byte-identical to enrollment every time, so decode() always
succeeds trivially. If you want to test the noisy-reconstruction path
later, that needs to be reintroduced deliberately, it isn't happening
here right now.
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
import puf_emulated
import fuzzy_extractor

IN_DIR = os.path.join(os.path.dirname(__file__), "in")
OUT_DIR = os.path.join(os.path.dirname(__file__), "out")


def select_root(store_nv: dict, n: int):
    """Pick the first root with unused intervals remaining (j_last < n)."""
    for root in store_nv["roots"]:
        if root["j_last"] < n:
            return root
    return None


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
    n = None  # recovered from flight_ctx below

    print("Phase 3: Pre-Flight Root Activation and Remote ID Broadcast")

    # --- pick a root with intervals remaining ---
    # n isn't stored top-level in Store_D_i^NV; read it from the first
    # root's flight_ctx, all roots share the same n in this prototype.
    if not store_nv["roots"]:
        print("ERROR: no roots in Store_D_i^NV. Enrollment did not complete.")
        sys.exit(1)
    n = store_nv["roots"][0]["flight_ctx"]["n"]

    root = select_root(store_nv, n)
    if root is None:
        print("Root exhausted: no root with unused intervals remains.")
        print("Select another authorized record or trigger renewal (Phase 2).")
        sys.exit(1)

    k = root["k"]
    print(f"Activating root k={k} (j_last={root['j_last']}, n={n})")

    # --- Activation ---
    S2 = fuzzy_extractor.fe_rec(
        puf_emulated.puf_response(store_nv["c2"], 64), store_nv["hd2"]
    )
    if S2 is None:
        print("ERROR: FE.Rec failed to reconstruct S2. Cannot activate this root.")
        sys.exit(1)

    seed_k = cp.kdf(S2, root["root_nonce"], k.to_bytes(4, "big"), pc.TAG_MERKLE_ROOT)

    leaves = []
    pids = []
    for j in range(n):
        j_bytes = j.to_bytes(4, "big")
        x_kj = cp.kdf(seed_k, j_bytes, pc.TAG_INTERVAL_SECRET)
        pid_kj = cp.hash_bytes(pc.TAG_RID + x_kj + j_bytes + root["root_nonce"])[:16]
        leaf = cp.hash_bytes(pc.TAG_LEAF + pid_kj + j_bytes + root["root_nonce"])
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
    # It is never written to uav_store_nv.json or any other file.
    active_state = {
        j: {"pid": pids[j], "leaf": leaves[j], "auth_path": merkle.auth_path(levels, j)}
        for j in range(n)
    }
    del S2, seed_k  # best-effort; see README on Python's lack of secure erasure

    j0 = root["j_last"] + 1
    if j0 > n:
        print("Root exhausted immediately (j_last already at n).")
        sys.exit(1)

    print(f"Activation complete. Broadcasting will resume from interval j={j0}.")

    # --- Broadcast loop ---
    delta_t = store_nv["roots"][0]["flight_ctx"]["delta_t"]
    log_path = os.path.join(OUT_DIR, "broadcast_log.jsonl")
    os.makedirs(OUT_DIR, exist_ok=True)

    t_activation = time.time()
    j = j0

    print(f"Starting broadcast loop (interval={delta_t}s, up to j={n})."
          f" Ctrl+C to stop early, progress is saved after every interval.")

    try:
        while j <= n:
            elapsed = time.time() - t_activation
            expected_j = j0 + int(elapsed // delta_t)
            if expected_j > j:
                j = expected_j
                if j > n:
                    break

            pid_hex = active_state[j - 1]["pid"].hex()
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

            print(f"  [j={j}/{n}] broadcast PID={pid_hex[:16]}...")

            # persist progress immediately, this is the reboot-recovery guarantee
            root["j_last"] = j
            pc.write_message(store_path, store_nv)

            j += 1
            time.sleep(delta_t)

    except KeyboardInterrupt:
        print(f"\nStopped early at j={root['j_last']}. State is saved; "
              f"rerunning this script will resume from j={root['j_last']+1}.")

    print(f"\nBroadcast log: {log_path}")
    print(f"Updated Store_D_i^NV: {store_path} (j_last={root['j_last']})")


if __name__ == "__main__":
    main()
