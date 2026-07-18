"""
verifier_phase4_process_response.py

Runs on: your computer (Verifier role, V_j).
Implements: the verifier's half of Algorithm 6, decrypt the payload,
verify AuthRec_i^(k) under PK_TA, check it against AuthDB_Vj, verify the
Merkle path, and verify sigma_D. The paper's final protocol has no
lightweight mode (see uav_phase4_session_and_respond.py's docstring for
why); this script always does the full Algorithm 6 verification now,
where an earlier version branched on a "mode" field the response no
longer carries.

BEFORE RUNNING: copy uav_response.json from the Pi's pi_side/out/ into
this script's in/ directory.
"""

import sys
import os
import json as _json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
import protocol_common as pc
import crypto_primitives as cp
import merkle
import tuple_hash256

import oqs

IN_DIR = os.path.join(os.path.dirname(__file__), "in")
OUT_DIR = os.path.join(os.path.dirname(__file__), "out")


def main():
    response_path = os.path.join(IN_DIR, "uav_response.json")
    pending_path = os.path.join(OUT_DIR, "verifier_session_pending_DO_NOT_SHARE.json")
    ta_public_path = os.path.join(OUT_DIR, "ta_public_params.json")
    auth_db_path = os.path.join(OUT_DIR, "verifier_AuthDB.json")

    for p in (response_path, pending_path, ta_public_path, auth_db_path):
        if not os.path.exists(p):
            print(f"ERROR: {p} not found.")
            sys.exit(1)

    response = pc.read_message(response_path)
    pending = pc.read_message(pending_path)
    ta_public = pc.read_message(ta_public_path)
    auth_db = pc.read_message(auth_db_path)

    ml_kem_alg = ta_public["ml_kem_alg"]
    ml_dsa_alg = ta_public["ml_dsa_alg"]
    pk_ta = ta_public["pk_ta"]

    print("Phase 4: On-demand authentication, verifier processing response")

    # --- ReqID (Eq. 10): recompute independently, cross-check against
    # what the UAV echoed back, rather than trusting it blindly. ---
    h_req_auth = cp.hash_bytes(pending["req_auth_bytes"])
    req_id = pc.compute_req_id(pending["req_auth_bytes"])
    if req_id != response["req_id"]:
        print("REJECT: ReqID mismatch (response does not match this request).")
        sys.exit(1)

    # --- Recover shared secret and session key ---
    with oqs.KeyEncapsulation(ml_kem_alg, pending["dk_vj"]) as kem:
        ss = kem.decap_secret(response["ct"])

    k_sess_full = cp.kdf(ss, pending["n_v"], pending["auth_ref"],
                          str(pending["ts_v"]).encode("utf-8"),
                          h_req_auth, pc.TAG_RID_AUTH)
    k_sess = k_sess_full[:16]

    # AEAD nonce, Eq. (11): deterministic, Trunc128(H256("AEAD-Nonce" ||
    # ReqID || ct)). Cross-check against what the response actually used
    # before trusting it for decryption.
    expected_nonce = pc.compute_aead_nonce(req_id, response["ct"])
    if expected_nonce != response["nonce"]:
        print("REJECT: AEAD nonce does not match the deterministic Eq. (11) derivation.")
        sys.exit(1)

    ad = pc.canonical_json_bytes({
        "req_id": req_id, "ct": response["ct"], "n_a": response["nonce"],
        "h_req_auth": h_req_auth,
    })
    plaintext = cp.aead_decrypt(k_sess, response["nonce"], ad, response["ciphertext"])
    if plaintext is None:
        print("REJECT: AEAD decryption/authentication failed.")
        sys.exit(1)

    payload = pc.decode_canonical_json(plaintext)
    print("  Decryption: OK")

    # --- Find the matching root record in AuthDB_Vj ---
    matching_record = None
    for rec in auth_db["root_records"]:
        if rec["pk_i"] and payload.get("root_nonce") and \
           rec["root_nonce"] == payload["root_nonce"]:
            matching_record = rec
            break

    if matching_record is None:
        print("REJECT: no matching root record in AuthDB_Vj for this RootNonce.")
        sys.exit(1)

    # --- Verify AuthRec_i^(k) under PK_TA ---
    auth_rec_sig = payload["auth_rec_signature"]
    flight_ctx_canonical = _json.dumps(matching_record["flight_ctx"], sort_keys=True).encode("utf-8")
    auth_rec_payload = (
        matching_record["pk_i"] + matching_record["mr_k"] +
        matching_record["root_nonce"] + flight_ctx_canonical
    )
    with oqs.Signature(ml_dsa_alg) as verifier:
        auth_rec_valid = verifier.verify(auth_rec_payload, auth_rec_sig, pk_ta)

    if not auth_rec_valid:
        print("REJECT: AuthRec_i^(k) does not verify under PK_TA.")
        sys.exit(1)
    print("  AuthRec_i^(k): VALID")

    # --- Verify Merkle path (Eq. 13, via the now-shared merkle.leaf_hash/
    # verify_path -- previously this script reimplemented the walk
    # locally with a plain H256 hash(left+right), not the paper's
    # H384/TupleHash leaf/node construction). flight_ctx comes from this
    # verifier's own AuthDB record, not the payload's copy of it, so a
    # malicious payload can't substitute a different context. ---
    j = payload["j"]
    pid_kj = payload["pid"]
    root_nonce = payload["root_nonce"]
    flight_ctx_bytes = pc.canonical_json_bytes(matching_record["flight_ctx"])
    leaf = merkle.leaf_hash(pid_kj, j, root_nonce, flight_ctx_bytes)

    mr_k = matching_record["mr_k"]
    merkle_valid = merkle.verify_path(leaf, j, payload["auth_path"], mr_k)
    print(f"  Merkle path: {'VALID' if merkle_valid else 'INVALID'}")

    if not merkle_valid:
        print("REJECT: Merkle path does not verify against MR_i^(k).")
        sys.exit(1)

    # --- Verify sigma_D (Algorithm 6 step 20-21). T_H recomputed with the
    # same H384/TupleHash construction and full field set the UAV used
    # (Algorithm 6 step 13): AuthRef, PID_{k,jcur}, jcur, MR_i^(k),
    # RootNonce_k, FlightCtx_k, N_V, TS_D, ct, H256(ReqAuthWire). An
    # earlier version of this check used H256 instead of H384, the wrong
    # domain tag, and only flight_ctx["scope"] instead of the full
    # context -- fixed to match uav_phase4_session_and_respond.py. ---
    sigma_d = payload["sigma_d"]
    t_h = tuple_hash256.tuple_hash256(
        pc.TAG_AUTH_TRANSCRIPT, pending["auth_ref"], pid_kj, j,
        mr_k, root_nonce, flight_ctx_bytes,
        pending["n_v"], str(payload["ts_d"]).encode("utf-8"), response["ct"], h_req_auth,
    )
    with oqs.Signature(ml_dsa_alg) as verifier:
        sig_valid = verifier.verify(t_h, sigma_d, matching_record["pk_i"])
    print(f"  Transcript signature (sigma_D): {'VALID' if sig_valid else 'INVALID'}")
    if not sig_valid:
        print("REJECT: sigma_D does not verify under PK_i.")
        sys.exit(1)

    print("\nACCEPT: signing identity and Merkle root both bound.")


if __name__ == "__main__":
    main()
