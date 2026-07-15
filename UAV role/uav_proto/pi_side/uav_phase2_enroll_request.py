"""
uav_phase2_enroll_request.py

Runs on: the Pi 5 (UAV role, D_i).
Implements: Algorithm 1 (UAV Enrollment and Merkle-Root Authorization),
the UAV-side steps up through sending RootReq_i^(k) to the TA, for each
of the m root windows.

BEFORE RUNNING: copy ta_public_params.json from the computer's
computer_side/out/ to this script's in/ directory (see README for the
exact path). This file is Phase 1's output and this script needs PK_TA's
companion Params (n, m, algorithm names) from it to stay consistent with
the TA.

Produces: out/uav_root_requests.json, containing one RootReq_i^(k) per
root window. Copy this file to the computer's computer_side/in/ directory
next, then run ta_phase2_enroll_process.py there.

ML-DSA keygen is now genuinely seeded/deterministic (see seeded_ml_dsa.py),
closing the gap flagged in earlier versions of this script: the same
seed_i^sig will regenerate the identical (PK_i, SK_i) later, which is
what Phase 4's strong-mode key-confirmation check depends on.
"""

import sys
import os
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
sys.path.insert(0, os.path.dirname(__file__))

import protocol_common as pc
import crypto_primitives as cp
import merkle
import puf_emulated
import fuzzy_extractor
import seeded_ml_dsa

import oqs

IN_DIR = os.path.join(os.path.dirname(__file__), "in")
OUT_DIR = os.path.join(os.path.dirname(__file__), "out")

UAV_CTX = b"uav-001"  # ctx_i: identifies this UAV in the KDF domain separation


def main():
    ta_params_path = os.path.join(IN_DIR, "ta_public_params.json")
    if not os.path.exists(ta_params_path):
        print(f"ERROR: {ta_params_path} not found.")
        print("Copy ta_public_params.json from the computer's "
              "computer_side/out/ into this script's in/ directory first.")
        sys.exit(1)

    ta_params = pc.read_message(ta_params_path)
    n = ta_params["n_intervals"]
    m = ta_params["m_roots"]
    ml_dsa_alg = ta_params["ml_dsa_alg"]

    print(f"Phase 2: UAV Enrollment (Algorithm 1), UAV side")
    print(f"Using TA params: n={n} intervals, m={m} roots, alg={ml_dsa_alg}")

    puf_emulated.reset_store()  # fresh "device" for this run

    # --- Extract hardware secrets (lines 2-3) ---
    C1 = secrets.token_bytes(16)
    C2 = secrets.token_bytes(16)
    R1 = puf_emulated.puf_response(C1, 64)
    R2 = puf_emulated.puf_response(C2, 64)

    S1, HD1 = fuzzy_extractor.fe_gen(R1)
    S2, HD2 = fuzzy_extractor.fe_gen(R2)
    print("PUF secrets extracted, fuzzy extractor helper data generated.")

    # --- Derive signing identity (lines 4-7) ---
    # Now genuinely seeded/deterministic (see seeded_ml_dsa.py); this closes
    # the gap flagged since the first Phase 2 delivery.
    seed_sig = cp.kdf(S1, pc.TAG_ML_DSA, UAV_CTX)
    PK_i, SK_i = seeded_ml_dsa.seeded_keygen(ml_dsa_alg, seed_sig)
    KC_i = cp.hash_bytes(PK_i)
    print(f"Signing key derived (seeded, deterministic): PK_i is {len(PK_i)} bytes, KC_i computed.")

    # --- Build m Merkle-root windows (lines 8-19) ---
    root_requests = []
    root_material_for_finalize = []  # kept locally, not sent to TA

    for k in range(m):
        root_nonce = secrets.token_bytes(16)
        flight_ctx = {
            "k": k,
            "delta_t": ta_params["delta_t_seconds"],
            "n": n,
            "validity": {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T23:59:59Z",
                         "max_intervals": n, "region": "TEST-REGION"},
            "scope": "test-deployment",
        }
        seed_k = cp.kdf(S2, root_nonce, k.to_bytes(4, "big"), pc.TAG_MERKLE_ROOT)

        leaves = []
        for j in range(n):
            j_bytes = j.to_bytes(4, "big")
            x_kj = cp.kdf(seed_k, j_bytes, pc.TAG_INTERVAL_SECRET)
            pid_kj = cp.hash_bytes(pc.TAG_RID + x_kj + j_bytes + root_nonce)[:16]
            leaf = cp.hash_bytes(pc.TAG_LEAF + pid_kj + j_bytes + root_nonce)
            leaves.append(leaf)

        levels = merkle.build_tree(leaves)
        mr_k = merkle.root(levels)

        root_requests.append({
            "k": k,
            "pk_i": PK_i,
            "hd1": HD1,
            "hd2": HD2,
            "c1": C1,
            "c2": C2,
            "mr_k": mr_k,
            "root_nonce": root_nonce,
            "flight_ctx": flight_ctx,
        })

        # kept on the UAV, not sent, needed later to finalize local storage
        root_material_for_finalize.append({
            "k": k,
            "root_nonce": root_nonce,
            "flight_ctx": flight_ctx,
            "mr_k": mr_k,
        })

        print(f"  Root window k={k}: MR_i^(k) = {mr_k.hex()[:16]}... built from {n} intervals")

    # --- Write the outgoing request (to be copied to the TA machine) ---
    outgoing_path = os.path.join(OUT_DIR, "uav_root_requests.json")
    pc.write_message(outgoing_path, {
        "uav_ctx": UAV_CTX,
        "requests": root_requests,
    })
    print(f"\nWrote root requests: {outgoing_path}")

    # --- Write local-only state needed to finalize after TA responds ---
    # NOT copied anywhere; this stays on the Pi. Includes SK_i, only for
    # this prototype run, see the seeded-keygen limitation in the docstring.
    local_state_path = os.path.join(OUT_DIR, "uav_local_pending_DO_NOT_SHARE.json")
    pc.write_message(local_state_path, {
        "sk_i": SK_i,
        "pk_i": PK_i,
        "kc_i": KC_i,
        "c1": C1,
        "c2": C2,
        "hd1": HD1,
        "hd2": HD2,
        "roots": root_material_for_finalize,
    })
    print(f"Wrote local pending state (do not copy): {local_state_path}")

    print(f"\nNext step: copy {os.path.basename(outgoing_path)} to the "
          f"computer's computer_side/in/ directory, then run "
          f"ta_phase2_enroll_process.py there.")


if __name__ == "__main__":
    main()
