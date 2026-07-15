"""
verifier_phase4_process_response.py

Runs on: your computer (Verifier role, V_j).
Implements: the verifier's half of Algorithm 5 (lightweight) or
Algorithm 6 (strong), whichever the UAV responded with, decrypt the
payload, verify AuthRec_i^(k) under PK_TA, check it against AuthDB_Vj,
verify the Merkle path, and (strong mode only) verify sigma_D.

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
    print(f"Response mode: {response['mode']}")

    # --- Recover shared secret and session key ---
    with oqs.KeyEncapsulation(ml_kem_alg, pending["dk_vj"]) as kem:
        ss = kem.decap_secret(response["ct"])

    h_req_auth = cp.hash_bytes(pending["req_auth_bytes"])
    k_sess_full = cp.kdf(ss, pending["n_v"], pending["pid"],
                          str(pending["ts_v"]).encode("utf-8"),
                          h_req_auth, pc.TAG_RID_AUTH)
    k_sess = k_sess_full[:16]

    ad = pending_scope = (auth_db["cert_vj"]["scope_j"].encode("utf-8") + h_req_auth)
    plaintext = cp.aead_decrypt(k_sess, response["nonce"], ad, response["ciphertext"])
    if plaintext is None:
        print("REJECT: AEAD decryption/authentication failed.")
        sys.exit(1)

    payload = pc.decode_canonical_json(plaintext)
    print("  Decryption: OK")

    # --- Find the matching root record in AuthDB_Vj ---
    mr_from_payload = None
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

    # --- Verify Merkle path ---
    j = payload["j"]
    pid_kj = payload["pid"]
    root_nonce = payload["root_nonce"]
    leaf = cp.hash_bytes(pc.TAG_LEAF + pid_kj + j.to_bytes(4, "big") + root_nonce)

    computed = leaf
    idx = j
    for sibling in payload["auth_path"]:
        if idx % 2 == 0:
            computed = cp.hash_bytes(computed + sibling)
        else:
            computed = cp.hash_bytes(sibling + computed)
        idx //= 2

    mr_k = matching_record["mr_k"]
    merkle_valid = (computed == mr_k)
    print(f"  Merkle path: {'VALID' if merkle_valid else 'INVALID'}")

    if not merkle_valid:
        print("REJECT: Merkle path does not verify against MR_i^(k).")
        sys.exit(1)

    if response["mode"] == "lightweight":
        print("\nACCEPT (lightweight): pseudonym is bound to an authorized "
              "Merkle root. Hardware possession demonstrated via X_k,j, "
              "no non-repudiable signing evidence.")
    else:
        sigma_d = payload["sigma_d"]
        t_h = cp.hash_bytes(
            pid_kj + mr_k + root_nonce + pending["n_v"] +
            str(payload["ts_d"]).encode("utf-8") + response["ct"] +
            h_req_auth + b"S" + matching_record["flight_ctx"]["scope"].encode("utf-8")
        )
        with oqs.Signature(ml_dsa_alg) as verifier:
            sig_valid = verifier.verify(t_h, sigma_d, matching_record["pk_i"])
        print(f"  Transcript signature (sigma_D): {'VALID' if sig_valid else 'INVALID'}")
        if not sig_valid:
            print("REJECT: sigma_D does not verify under PK_i.")
            sys.exit(1)
        print("\nACCEPT (strong): signing identity and Merkle root both bound.")


if __name__ == "__main__":
    main()
