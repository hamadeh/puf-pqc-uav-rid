"""Decrypt and verify the canonical Algorithm-6 UAV response."""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import oqs

import crypto_primitives as cp
import merkle
import protocol_common as pc
import protocol_messages as pm
import revocation

BASE = os.path.dirname(__file__)
IN_DIR = os.path.join(BASE, "in")
OUT_DIR = os.path.join(BASE, "out")
EXPECTED_REGION = "TEST-REGION"


def reject(message: str) -> None:
    raise SystemExit(f"REJECT: {message}")


def main() -> None:
    response_path = os.path.join(IN_DIR, "uav_response.bin")
    pending = pc.read_message(os.path.join(
        OUT_DIR, "verifier_session_pending_DO_NOT_SHARE.json"
    ))
    params = pc.read_message(os.path.join(OUT_DIR, "ta_public_params.json"))
    auth_db = pc.read_message(os.path.join(OUT_DIR, "verifier_AuthDB.json"))
    response = pm.decode_response_outer(open(response_path, "rb").read())
    req_wire = pending["req_wire"]
    request_hash = cp.hash_bytes(req_wire)
    req_id = pc.compute_req_id(req_wire)
    if response["req_id"] != req_id:
        reject("ReqID mismatch")
    expected_nonce = pc.compute_aead_nonce(req_id, response["ct"])
    if response["nonce"] != expected_nonce:
        reject("noncanonical AEAD nonce")
    with oqs.KeyEncapsulation(
        params["ml_kem_alg"], pending["dk_vj"]
    ) as kem:
        ss = kem.decap_secret(response["ct"])
    k_sess = pc.kdf_labeled(
        pc.TAG_RID_AUTH, ss, req_id, request_hash
    )[:16]
    ad = pm.encode_aead_ad(
        req_id, response["ct"], response["nonce"], request_hash
    )
    plaintext = cp.aead_decrypt(
        k_sess, response["nonce"], ad, response["ciphertext"]
    )
    if plaintext is None:
        reject("AEAD authentication failed")
    payload = pm.decode_payload(plaintext)
    if payload["auth_ref"] != pending["auth_ref"] or payload["pid"] != pending["auth_ref"]:
        reject("response does not bind the captured AuthRef")
    now = int(time.time())
    if abs(now - payload["ts_d"]) > params["freshness_tolerance_seconds"]:
        reject("stale UAV response timestamp")

    rl = revocation.verify_record(
        auth_db["rl_record"], params["pk_ta"]
    )
    matching = next(
        (record for record in auth_db["root_records"]
         if record["root_id"] == payload["root_id"]), None
    )
    if matching is None:
        reject("RootID absent from verifier AuthDB")
    auth_body, auth_sig = pm.decode_signed_record(
        matching["auth_record"], pm.TYPE_AUTH_RECORD
    )
    root = pm.decode_root_auth_body(auth_body)
    with oqs.Signature(params["ml_dsa_alg"]) as verifier:
        if not verifier.verify(auth_body, auth_sig, params["pk_ta"]):
            reject("invalid TA root authorization")
    revocation.assert_not_revoked(
        rl, root_id=payload["root_id"],
        key_id_value=revocation.key_id(root["pk_i"]),
    )
    ctx = root["flight_ctx"]
    if ctx["scope"] != pending["requested_scope"] or ctx["region"] != EXPECTED_REGION:
        reject("root scope or region mismatch")
    if not ctx["start_time"] <= pending["ts_v"] <= ctx["end_time"]:
        reject("request timestamp outside root validity")
    expected_j = 1 + (
        pending["ts_v"] - ctx["start_time"]
    ) // ctx["delta_t"]
    if payload["j"] != expected_j or not 1 <= expected_j <= ctx["n"]:
        reject("interval index is inconsistent with verifier timestamp")
    leaf = merkle.leaf_hash(
        payload["pid"], payload["j"], root["root_nonce"],
        root["flight_ctx_wire"],
    )
    if not merkle.verify_path(
        leaf, payload["j"], payload["auth_path"], root["mr_k"], ctx["n"]
    ):
        reject("invalid Merkle authentication path")
    transcript = pm.encode_auth_transcript(
        req_id, pending["auth_ref"], payload["pid"], payload["j"],
        payload["root_id"], pending["n_v"], pending["ts_v"],
        payload["ts_d"], response["ct"],
    )
    with oqs.Signature(params["ml_dsa_alg"]) as verifier:
        if not verifier.verify(transcript, payload["sigma_d"], root["pk_i"]):
            reject("invalid UAV transcript signature")
    print("ACCEPT: certificate, revocation, time, Merkle, and UAV signature checks passed.")


if __name__ == "__main__":
    main()
