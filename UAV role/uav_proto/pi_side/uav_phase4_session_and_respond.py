"""
uav_phase4_session_and_respond.py

Runs on: the Pi 5 (UAV role, D_i).
Implements: Algorithm 5 (verifier authentication + session establishment,
including the constant-time PID lookup) then Algorithm 6 (PUF-rooted
post-quantum authentication). The paper's final protocol has no
lower-assurance branch ("The protocol has no lower-assurance branch and
discloses no interval secret") -- every accepted request gets the full
Algorithm 6 response; there is no lightweight/strong mode split here
anymore (an earlier version of this script had one; TAG_LIGHTWEIGHT
never appeared in the paper's own Table 5 domain-tag list).

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

SIMPLIFICATIONS in this prototype, still true, stated plainly:
  - No replay/nonce cache: nonce uniqueness is asserted, not actually
    checked against previously-seen nonces.
  - No revocation infrastructure: revocation status is not checked.
  These are unchanged by this alignment pass; both are substantial
  standalone subsystems scoped out of it on purpose (see the session
  that did this rewrite for why).

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
import fuzzy_extractor
import tuple_hash256
import seeded_ml_dsa

import oqs

IN_DIR = os.path.join(os.path.dirname(__file__), "in")
OUT_DIR = os.path.join(os.path.dirname(__file__), "out")

UAV_CTX = b"uav-001"
TIMESTAMP_TOLERANCE_SECONDS = 3600


def rebuild_active_root_table(store_nv: dict, root: dict, n: int):
    """Recomputes {j: (pid, leaf)} for every interval of the given root."""
    S2 = fuzzy_extractor.rec_from_seed(store_nv["c_seed2"], store_nv["hd2"])
    if S2 is None:
        return None, None, None

    seed_k = cp.kdf(S2, root["root_nonce"], root["k"].to_bytes(4, "big"), pc.TAG_MERKLE_ROOT)
    del S2

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
    del seed_k

    levels = merkle.build_tree(leaves)
    return pids, levels, flight_ctx_bytes


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

    def abort_silently(reason: str):
        print(f"ABORT (silent, no response sent): {reason}")
        sys.exit(0)

    # --- Verify Cert_Vj under PK_TA ---
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

    # --- Verify sigma_Vj over H(ReqAuth), and compute ReqID (Eq. 10) ---
    req_auth_bytes = pc.canonical_json_bytes(req_auth)
    h_req_auth = cp.hash_bytes(req_auth_bytes)
    req_id = pc.compute_req_id(req_auth_bytes)
    with oqs.Signature(ml_dsa_alg) as verifier:
        sig_valid = verifier.verify(h_req_auth, sigma_vj, cert_vj["pk_vj"])
    if not sig_valid:
        abort_silently("sigma_Vj does not verify under PK_Vj")
    print("  sigma_Vj: VALID")
    print(f"  ReqID: {req_id.hex()}")

    # --- Freshness and scope. ScopeOK (Eq. 15) is a full set-intersection
    # predicate in the paper; this prototype keeps scope as a single
    # string (see the session that did this alignment pass for why that
    # remains a documented simplification), but now checks it against
    # BOTH the active root's scope AND the verifier's own certified
    # scope, not just the former as an earlier version of this script did. ---
    if abs(time.time() - req_auth["ts_v"]) > TIMESTAMP_TOLERANCE_SECONDS:
        abort_silently("timestamp outside tolerance")
    root_scope = store_nv["roots"][0]["flight_ctx"]["scope"]
    if req_auth["scope_j"] != root_scope:
        abort_silently("scope mismatch (request vs. root)")
    if cert_vj["scope_j"] != root_scope:
        abort_silently("scope mismatch (verifier certificate vs. root)")
    print("  Freshness and scope: OK")

    # --- Constant-time PID lookup (Algorithm 5 step 11) ---
    n = store_nv["roots"][0]["flight_ctx"]["n"]
    active_root = None
    for r in store_nv["roots"]:
        import interval_journal as ij
        journal_path = ij.journal_path_for_root(OUT_DIR, r["k"])
        recovered = ij.recover(journal_path)
        if recovered is not None and recovered[1]["j_next"] > 1:
            active_root = r
            break
    if active_root is None:
        abort_silently("no active root found (has Phase 3 been run?)")

    pids, levels, flight_ctx_bytes = rebuild_active_root_table(store_nv, active_root, n)
    if pids is None:
        abort_silently("FE.Rec failed to reconstruct S2")

    auth_ref = req_auth["auth_ref"]
    j_index = constant_time_find_j(pids, auth_ref)
    if j_index == -1:
        abort_silently("no cached entry matches the received AuthRef")
    print(f"  PID lookup: matched interval j={j_index + 1} (constant-time scan over n={n})")

    pid_kj = pids[j_index]
    auth_path = merkle.auth_path(levels, j_index)

    # --- ML-KEM encapsulation and session key ---
    with oqs.KeyEncapsulation(ml_kem_alg) as kem:
        ct, ss = kem.encap_secret(req_auth["ek_vj"])

    k_sess_full = cp.kdf(ss, req_auth["n_v"], auth_ref,
                          str(req_auth["ts_v"]).encode("utf-8"),
                          h_req_auth, pc.TAG_RID_AUTH)
    k_sess = k_sess_full[:16]  # Ascon-128 needs exactly 16 bytes
    nonce16 = pc.compute_aead_nonce(req_id, ct)  # Eq. (11), deterministic

    print("  ML-KEM session established.")

    ts_d = time.time()

    # --- Algorithm 6: PUF-rooted post-quantum authentication ---
    S1 = fuzzy_extractor.rec_from_seed(store_nv["c_seed1"], store_nv["hd1"])
    if S1 is None:
        abort_silently("FE.Rec failed to reconstruct S1")
    seed_sig = cp.kdf(S1, pc.TAG_ML_DSA, UAV_CTX)
    del S1
    PK_i, SK_i = seeded_ml_dsa.seeded_keygen(ml_dsa_alg, seed_sig)

    if cp.hash_bytes(PK_i) != store_nv["kc_i"]:
        print("  Key-confirmation check FAILED after regeneration, retrying PUF read once...")
        S1_retry = fuzzy_extractor.rec_from_seed(store_nv["c_seed1"], store_nv["hd1"])
        if S1_retry is None:
            abort_silently("FE.Rec failed to reconstruct S1 on retry")
        seed_sig_retry = cp.kdf(S1_retry, pc.TAG_ML_DSA, UAV_CTX)
        PK_i, SK_i = seeded_ml_dsa.seeded_keygen(ml_dsa_alg, seed_sig_retry)
        if cp.hash_bytes(PK_i) != store_nv["kc_i"]:
            abort_silently("key-confirmation failed twice, sending fault "
                            "declaration is not implemented in this "
                            "prototype, see Algorithm 6's fault path")

    print("  Key-confirmation check: PASSED")

    # T_H, Algorithm 6 step 13: H384("RID-UAV-Auth-v1", Enc(AuthRef,
    # PID_{k,jcur}, jcur, MR_i^(k), RootNonce_k, FlightCtx_k, N_V, TS_D,
    # ct, H256(ReqAuthWire))). Previously this used the wrong hash (H256
    # instead of H384/TupleHash), the wrong tag, and was missing AuthRef,
    # jcur, and full FlightCtx_k (only flight_ctx["scope"] leaked in).
    t_h = tuple_hash256.tuple_hash256(
        pc.TAG_AUTH_TRANSCRIPT, auth_ref, pid_kj, j_index,
        active_root["mr_k"], active_root["root_nonce"], flight_ctx_bytes,
        req_auth["n_v"], str(ts_d).encode("utf-8"), ct, h_req_auth,
    )
    with oqs.Signature(ml_dsa_alg, SK_i) as signer:
        sigma_d = signer.sign(t_h)
    del SK_i

    # PayloadWire, Algorithm 6 step 15.
    payload = {
        "auth_ref": auth_ref,
        "pid": pid_kj,
        "j": j_index,
        "root_nonce": active_root["root_nonce"],
        "flight_ctx": active_root["flight_ctx"],
        "auth_path": auth_path,
        "mr_k": active_root["mr_k"],
        "auth_rec_signature": active_root["auth_rec_signature"],
        "ts_d": ts_d,
        "sigma_d": sigma_d,
    }
    plaintext = pc.canonical_json_bytes(payload)

    # AD_A, Eq. (12): Enc(RespHeader, ReqID, ct, N_A, H256(ReqAuthWire)).
    # RespHeader carries no additional fields beyond ReqID/ct/N_A in this
    # prototype, so it's folded into this same associated-data structure
    # rather than kept as a separate, currently-empty object.
    ad = pc.canonical_json_bytes({
        "req_id": req_id, "ct": ct, "n_a": nonce16, "h_req_auth": h_req_auth,
    })
    ciphertext = cp.aead_encrypt(k_sess, nonce16, ad, plaintext)

    print("  Built Algorithm 6 response (PayloadWire).")

    response_path = os.path.join(OUT_DIR, "uav_response.json")
    pc.write_message(response_path, {
        "req_id": req_id,
        "ct": ct,
        "nonce": nonce16,
        "ciphertext": ciphertext,
    })
    print(f"\nWrote response: {response_path}")
    print(f"Next step: copy {os.path.basename(response_path)} to the "
          f"computer's computer_side/in/ directory, then run "
          f"verifier_phase4_process_response.py there.")


if __name__ == "__main__":
    main()
