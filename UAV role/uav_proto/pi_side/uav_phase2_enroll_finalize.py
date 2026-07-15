"""
uav_phase2_enroll_finalize.py

Runs on: the Pi 5 (UAV role, D_i).
Implements: Algorithm 1's closing steps, verify each AuthRec_i^(k) the
TA returned, then write Store_{D_i}^{NV} (Eq. uav_nonvolatile_storage)
and erase the transient secrets (S1, S2, Seed_k, X_{k,j}; already out
of scope by this point, they were never written to disk in the first
place, see uav_phase2_enroll_request.py).

BEFORE RUNNING: copy ta_authrec_response.json from the computer's
computer_side/out/ into this script's in/ directory.

Produces: out/uav_store_nv.json, this is Store_{D_i}^{NV}, the UAV's
actual persistent enrollment record. Phase 3 (root activation) will read
this file. It is safe to keep on the Pi; it contains no PUF secrets,
seeds, or SK_i, matching the paper's design (Eq. uav_nonvolatile_storage
explicitly excludes S1, S2, Seed_k, X_{k,j}, SK_i).
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
sys.path.insert(0, os.path.dirname(__file__))

import protocol_common as pc

import oqs

IN_DIR = os.path.join(os.path.dirname(__file__), "in")
OUT_DIR = os.path.join(os.path.dirname(__file__), "out")


def main():
    response_path = os.path.join(IN_DIR, "ta_authrec_response.json")
    local_pending_path = os.path.join(OUT_DIR, "uav_local_pending_DO_NOT_SHARE.json")
    ta_params_path = os.path.join(IN_DIR, "ta_public_params.json")

    for p in (response_path, local_pending_path, ta_params_path):
        if not os.path.exists(p):
            print(f"ERROR: {p} not found.")
            sys.exit(1)

    response = pc.read_message(response_path)
    pending = pc.read_message(local_pending_path)
    ta_params = pc.read_message(ta_params_path)

    pk_ta = ta_params["pk_ta"]
    ml_dsa_alg = ta_params["ml_dsa_alg"]
    pk_i = pending["pk_i"]

    print("Phase 2: UAV Enrollment (Algorithm 1), UAV finalize step")
    print(f"Verifying {len(response['auth_recs'])} AuthRec records from TA...")

    store_nv_records = []

    with oqs.Signature(ml_dsa_alg) as verifier:
        # index local root material by k for lookup
        roots_by_k = {r["k"]: r for r in pending["roots"]}

        for auth_rec in response["auth_recs"]:
            k = auth_rec["k"]
            signature = auth_rec["signature"]

            if k not in roots_by_k:
                print(f"  WARNING: TA returned AuthRec for unknown k={k}, skipping.")
                continue

            root_info = roots_by_k[k]
            root_nonce = root_info["root_nonce"]
            flight_ctx = root_info["flight_ctx"]
            mr_k = root_info["mr_k"]

            flight_ctx_canonical = json.dumps(flight_ctx, sort_keys=True).encode("utf-8")
            expected_payload = pk_i + mr_k + root_nonce + flight_ctx_canonical

            is_valid = verifier.verify(expected_payload, signature, pk_ta)
            status = "VALID" if is_valid else "INVALID"
            print(f"  AuthRec_i^(k={k}): signature {status}")

            if not is_valid:
                print(f"  Refusing to store AuthRec_i^(k={k}), signature check failed.")
                continue

            store_nv_records.append({
                "k": k,
                "root_nonce": root_nonce,
                "flight_ctx": flight_ctx,
                "auth_rec_signature": signature,
                "mr_k": mr_k,
                "j_last": 0,  # per the paper: unused root starts at interval 0
            })

    if not store_nv_records:
        print("\nNo valid AuthRec records to store. Enrollment did not complete.")
        sys.exit(1)

    # Store_{D_i}^{NV} (Eq. uav_nonvolatile_storage): C1, C2, HD1, HD2,
    # Params, KC_i, and per-root {RootNonce_k, FlightCtx_k, AuthRec_i^(k),
    # k, Validity_k, j_last^(k)}. Deliberately excludes S1, S2, Seed_k,
    # X_{k,j}, SK_i, matching the paper's design.
    store_nv = {
        "c1": pending["c1"],
        "c2": pending["c2"],
        "hd1": pending["hd1"],
        "hd2": pending["hd2"],
        "kc_i": pending["kc_i"],
        "pk_i": pk_i,
        "roots": store_nv_records,
    }

    store_path = os.path.join(OUT_DIR, "uav_store_nv.json")
    pc.write_message(store_path, store_nv)
    print(f"\nWrote Store_D_i^NV: {store_path}")
    print(f"Enrolled with {len(store_nv_records)} valid root(s).")

    print("\nCleaning up local pending state (contained SK_i and PUF-derived "
          "secrets, no longer needed now that enrollment is finalized)...")
    os.remove(local_pending_path)
    print(f"Removed: {local_pending_path}")
    print("\nNote: Python's garbage collector does not guarantee secure "
          "erasure of the SK_i bytes that were in memory (see README), "
          "this removes the file on disk, not the in-process copy.")


if __name__ == "__main__":
    main()
