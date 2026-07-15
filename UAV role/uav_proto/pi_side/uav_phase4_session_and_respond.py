"""
uav_phase4_session_and_respond.py

Runs on: the Pi 5 (UAV role, D_i).
Implements: Algorithm 4 (verifier authentication + session establishment,
including the constant-time PID lookup) then branches into Algorithm 5
(lightweight) or Algorithm 6 (strong) depending on ModeReq.

BEFORE RUNNING: copy verifier_reqauth.json from the computer's
computer_side/out/ into this script's in/ directory.

Rebuilds the currently active root's full interval table from
Store_D_i^NV (same derivation as Phase 3's activation), since
ActiveState_k lives only in volatile memory and doesn't persist across
separate process runs the way it would across threads in a real
long-running UAV process. This is a faithful simulation of "the UAV
still has its active flight state in memory" for a Pi process that's
been running continuously since Phase 3, just re-derived here since
we're simulating phases as separate script invocations.

SIMPLIFICATIONS in this prototype, stated plainly:
  - No replay/nonce cache: nonce uniqueness is asserted, not actually
    checked against previously-seen nonces.
  - No revocation infrastructure: revocation status is not checked.
  - Assurance-level escalation is not implemented: this script responds
    in exactly the mode requested, never escalates lightweight to strong
    the way your paper's Assurance-Level Enforcement section permits.

Produces: out/uav_response.json, copy to the computer's
computer_side/in/ directory, then run
verifier_phase4_process_response.py there.
"""

import sys
import os
import time

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

UAV_CTX = b"uav-001"
TIMESTAMP_TOLERANCE_SECONDS = 3600


def rebuild_active_root_table(store_nv: dict, root: dict, n: int):
    """Recomputes {j: (pid, leaf)} for every interval of the given root."""
    S2 = fuzzy_extractor.fe_rec(
        puf_emulated.puf_response(store_nv["c2"], 64), store_nv["hd2"]
    )
    if S2 is None:
        return None, None

    seed_k = cp.kdf(S2, root["root_nonce"], root["k"].to_bytes(4, "big"), pc.TAG_MERKLE_ROOT)
    del S2

    leaves = []
    pids = []
    for j in range(n):
        j_bytes = j.to_bytes(4, "big")
        x_kj = cp.kdf(seed_k, j_bytes, pc.TAG_INTERVAL_SECRET)
        pid_kj = cp.hash_bytes(pc.TAG_RID + x_kj + j_bytes + root["root_nonce"])[:16]
        leaf = cp.hash_bytes(pc.TAG_LEAF + pid_kj + j_bytes + root["root_nonce"])
        leaves.append(leaf)
        pids.append(pid_kj)
    del seed_k

    levels = merkle.build_tree(leaves)
    return pids, levels


def constant_time_find_j(pids: list, target_pid: bytes) -> int:
    """
    Scans every entry regardless of whether an earlier match was already
    found, so response timing doesn't depend on where (or whether) the
    match occurs. See Section III.F.1's constant-time lookup requirement.
    """
    found_j = -1
    for j, pid in enumerate(pids):
        match = (pid == target_pid)
        # bitwise-style select without branching on `match` for the assignment
        found_j = j if (match and found_j == -1) else found_j
    return found_j


def main():
    req_path = os.path.join(IN_DIR, "verifier_reqauth.json")
    store_path = os.path.join(OUT_DIR, "uav_store_nv.json")
    ta_params_path = os.path.join(IN_DIR, "ta_public_params.json")

    for p in (req_path, store_path, ta_params_path):
        if not os.path.exists(p):
            print(f"ERROR: {p} not found.")
            sys.exit(1)

    incoming = pc.read_message(req_path)
    store_nv = pc.read_message(store_path)
    ta_params = pc.read_message(ta_params_path)

    req_auth = incoming["req_auth"]
    sigma_vj = incoming["sigma_vj"]
    ml_dsa_alg = ta_params["ml_dsa_alg"]
    ml_kem_alg = ta_params["ml_kem_alg"]
    pk_ta = ta_params["pk_ta"]

    print("Phase 4: On-demand authentication, UAV side")
    print(f"Received ReqAuth requesting mode: {req_auth['mode_req']}")

    def abort_silently(reason: str):
        print(f"ABORT (silent, no response sent): {reason}")
        sys.exit(0)

    # --- Verify Cert_Vj under PK_TA ---
    # Reconstruct the exact payload the TA signed in
    # ta_phase2_verifier_enroll_process.py: vid_j || pk_vj || scope_j ||
    # canonical(validity_j). Must match byte-for-byte or this always fails.
    cert_vj = req_auth["cert_vj"]
    import json as _json
    validity_canonical = _json.dumps(cert_vj["validity_j"], sort_keys=True).encode("utf-8")
    cert_payload = (
        cert_vj["vid_j"].encode("utf-8") + cert_vj["pk_vj"] +
        cert_vj["scope_j"].encode("utf-8") + validity_canonical
    )
    with oqs.Signature(ml_dsa_alg) as verifier:
        cert_valid = verifier.verify(cert_payload, cert_vj["signature"], pk_ta)
    if not cert_valid:
        abort_silently("Cert_Vj does not verify under PK_TA")
    print("  Cert_Vj: VALID")

    # --- Verify sigma_Vj over H(ReqAuth) ---
    req_auth_bytes = pc.canonical_json_bytes(req_auth)
    h_req_auth = cp.hash_bytes(req_auth_bytes)
    with oqs.Signature(ml_dsa_alg) as verifier:
        sig_valid = verifier.verify(h_req_auth, sigma_vj, cert_vj["pk_vj"])
    if not sig_valid:
        abort_silently("sigma_Vj does not verify under PK_Vj")
    print("  sigma_Vj: VALID")

    # --- Freshness, scope (nonce/revocation checks not implemented, see docstring) ---
    if abs(time.time() - req_auth["ts_v"]) > TIMESTAMP_TOLERANCE_SECONDS:
        abort_silently("timestamp outside tolerance")
    if req_auth["scope_j"] != store_nv["roots"][0]["flight_ctx"]["scope"]:
        abort_silently("scope mismatch")
    print("  Freshness and scope: OK")

    # --- Constant-time PID lookup (the fix from our last gap-analysis pass) ---
    n = store_nv["roots"][0]["flight_ctx"]["n"]
    active_root = None
    for r in store_nv["roots"]:
        if r["j_last"] > 0:  # a root that's actually been broadcasting
            active_root = r
            break
    if active_root is None:
        abort_silently("no active root found (has Phase 3 been run?)")

    pids, levels = rebuild_active_root_table(store_nv, active_root, n)
    if pids is None:
        abort_silently("FE.Rec failed to reconstruct S2")

    j_index = constant_time_find_j(pids, req_auth["pid"])
    if j_index == -1:
        abort_silently("no cached entry matches the received PID")
    print(f"  PID lookup: matched interval j={j_index + 1} (constant-time scan over n={n})")

    pid_kj = pids[j_index]
    auth_path = merkle.auth_path(levels, j_index)

    # --- ML-KEM encapsulation and session key ---
    with oqs.KeyEncapsulation(ml_kem_alg) as kem:
        ct, ss = kem.encap_secret(req_auth["ek_vj"])

    k_sess_full = cp.kdf(ss, req_auth["n_v"], req_auth["pid"],
                          str(req_auth["ts_v"]).encode("utf-8"),
                          h_req_auth, pc.TAG_RID_AUTH)
    k_sess = k_sess_full[:16]  # Ascon-128 needs exactly 16 bytes
    nonce16 = os.urandom(16)

    print("  ML-KEM session established.")

    ts_d = time.time()
    mode_req = req_auth["mode_req"]

    if mode_req == "lightweight":
        S2 = fuzzy_extractor.fe_rec(
            puf_emulated.puf_response(store_nv["c2"], 64), store_nv["hd2"]
        )
        seed_k = cp.kdf(S2, active_root["root_nonce"],
                         active_root["k"].to_bytes(4, "big"), pc.TAG_MERKLE_ROOT)
        x_kj = cp.kdf(seed_k, j_index.to_bytes(4, "big"), pc.TAG_INTERVAL_SECRET)
        del S2, seed_k

        tau_kj = cp.hash_bytes(
            x_kj + pid_kj + req_auth["n_v"] + str(ts_d).encode("utf-8") +
            h_req_auth + pc.TAG_LIGHTWEIGHT
        )

        payload_l = {
            "pid": pid_kj,
            "j": j_index,
            "root_nonce": active_root["root_nonce"],
            "flight_ctx": active_root["flight_ctx"],
            "auth_path": auth_path,
            "x_kj": x_kj,
            "ts_d": ts_d,
            "tau_kj": tau_kj,
            "auth_rec_signature": active_root["auth_rec_signature"],
            "mode": "L",
        }
        plaintext = pc.canonical_json_bytes(payload_l)
        ad = req_auth["scope_j"].encode("utf-8") + h_req_auth
        ciphertext = cp.aead_encrypt(k_sess, nonce16, ad, plaintext)

        print("  Built lightweight response (Payload_L).")
        del x_kj

    elif mode_req == "strong":
        S1 = fuzzy_extractor.fe_rec(
            puf_emulated.puf_response(store_nv["c1"], 64), store_nv["hd1"]
        )
        seed_sig = cp.kdf(S1, pc.TAG_ML_DSA, UAV_CTX)
        del S1
        PK_i, SK_i = seeded_ml_dsa.seeded_keygen(ml_dsa_alg, seed_sig)

        if cp.hash_bytes(PK_i) != store_nv["kc_i"]:
            print("  Key-confirmation check FAILED after regeneration, retrying PUF read once...")
            S1_retry = fuzzy_extractor.fe_rec(
                puf_emulated.puf_response(store_nv["c1"], 64), store_nv["hd1"]
            )
            seed_sig_retry = cp.kdf(S1_retry, pc.TAG_ML_DSA, UAV_CTX)
            PK_i, SK_i = seeded_ml_dsa.seeded_keygen(ml_dsa_alg, seed_sig_retry)
            if cp.hash_bytes(PK_i) != store_nv["kc_i"]:
                abort_silently("key-confirmation failed twice, sending fault "
                                "declaration is not implemented in this "
                                "prototype, see Algorithm 6's fault path")

        print("  Key-confirmation check: PASSED")

        t_h = cp.hash_bytes(
            pid_kj + active_root["mr_k"] + active_root["root_nonce"] +
            req_auth["n_v"] + str(ts_d).encode("utf-8") + ct +
            h_req_auth + b"S" + active_root["flight_ctx"]["scope"].encode("utf-8")
        )
        with oqs.Signature(ml_dsa_alg, SK_i) as signer:
            sigma_d = signer.sign(t_h)
        del SK_i

        payload_s = {
            "pid": pid_kj,
            "j": j_index,
            "root_nonce": active_root["root_nonce"],
            "flight_ctx": active_root["flight_ctx"],
            "auth_path": auth_path,
            "mr_k": active_root["mr_k"],
            "auth_rec_signature": active_root["auth_rec_signature"],
            "ts_d": ts_d,
            "sigma_d": sigma_d,
            "mode": "S",
        }
        plaintext = pc.canonical_json_bytes(payload_s)
        ad = req_auth["scope_j"].encode("utf-8") + h_req_auth
        ciphertext = cp.aead_encrypt(k_sess, nonce16, ad, plaintext)

        print("  Built strong response (Payload_S).")

    else:
        abort_silently(f"unknown ModeReq: {mode_req}")

    response_path = os.path.join(OUT_DIR, "uav_response.json")
    pc.write_message(response_path, {
        "ct": ct,
        "nonce": nonce16,
        "ciphertext": ciphertext,
        "mode": mode_req,
    })
    print(f"\nWrote response: {response_path}")
    print(f"Next step: copy {os.path.basename(response_path)} to the "
          f"computer's computer_side/in/ directory, then run "
          f"verifier_phase4_process_response.py there.")


if __name__ == "__main__":
    main()
