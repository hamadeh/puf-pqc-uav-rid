"""
verifier_phase4_request.py

Runs on: your computer (Verifier role, V_j).
Implements: Algorithm 5, the verifier's half, generate a nonce and
ephemeral ML-KEM pair, form ReqAuth around a captured pseudonym, and sign it.

BEFORE RUNNING: copy the Pi's pi_side/out/broadcast_log.jsonl into this
script's in/ directory (simulating a receiver having captured Remote ID
broadcasts). This script reads the LAST line of that file, standing in
for "the most recently observed pseudonym."

ReqAuth carries AuthRef, the raw observed pseudonym bytes (Profile P: a
verifier has no way to know which root or interval produced a given
broadcast, that opacity is the entire point of Phase 3, so it can only
ever send what it actually captured; the UAV recovers k and j itself,
see uav_phase4_session_and_respond.py's constant-time scan).

Produces:
  out/verifier_reqauth.json: copy to the Pi's pi_side/in/ directory.
  out/verifier_session_pending_DO_NOT_SHARE.json: stays here, holds
      dk_Vj (needed later to decapsulate the UAV's response) and the
      exact ReqAuth bytes this script hashed and signed, the UAV's
      response verification needs to reconstruct H(ReqAuth) identically.

ALIGNED WITH THE PAPER: the paper's final Algorithm 5+6 has no
lightweight/strong mode split ("The protocol has no lower-assurance
branch"), so MODE_REQ is gone; every request gets the full PUF-rooted
response. The "pid" field is renamed "auth_ref" to match the paper's
terminology (AuthRef = PID under Profile P).
"""

import sys
import os
import time
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
import protocol_common as pc
import crypto_primitives as cp

import oqs

IN_DIR = os.path.join(os.path.dirname(__file__), "in")
OUT_DIR = os.path.join(os.path.dirname(__file__), "out")

VERIFIER_SCOPE = "test-deployment"


def main():
    broadcast_log_path = os.path.join(IN_DIR, "broadcast_log.jsonl")
    secret_path = os.path.join(OUT_DIR, "verifier_secret_DO_NOT_SHARE.json")
    ta_public_path = os.path.join(OUT_DIR, "ta_public_params.json")

    for p in (broadcast_log_path, secret_path, ta_public_path):
        if not os.path.exists(p):
            print(f"ERROR: {p} not found.")
            sys.exit(1)

    with open(broadcast_log_path) as f:
        lines = [l for l in f if l.strip()]
    if not lines:
        print("ERROR: broadcast_log.jsonl is empty, nothing to authenticate.")
        sys.exit(1)

    last_broadcast = json.loads(lines[-1])
    auth_ref = bytes.fromhex(last_broadcast["pid"])
    print(f"Phase 4: On-demand authentication, verifier side")
    print(f"Observed pseudonym (most recent capture): {auth_ref.hex()[:16]}...")

    verifier_secret = pc.read_message(secret_path)
    sk_vj = verifier_secret["sk_vj"]
    vid_j = verifier_secret["vid_j"]
    ta_public = pc.read_message(ta_public_path)
    ml_dsa_alg = ta_public["ml_dsa_alg"]
    ml_kem_alg = ta_public["ml_kem_alg"]

    # Need Cert_Vj (issued during Phase 2 verifier enrollment) to include
    # in ReqAuth; it's stored in verifier_AuthDB.json's cert_vj field.
    auth_db_path = os.path.join(OUT_DIR, "verifier_AuthDB.json")
    if not os.path.exists(auth_db_path):
        print(f"ERROR: {auth_db_path} not found. Run Phase 2 verifier "
              f"enrollment first.")
        sys.exit(1)
    auth_db = pc.read_message(auth_db_path)
    cert_vj = auth_db["cert_vj"]

    # --- Algorithm 5, verifier steps ---
    with oqs.KeyEncapsulation(ml_kem_alg) as kem:
        ek_vj = kem.generate_keypair()
        dk_vj = kem.export_secret_key()

    n_v = os.urandom(16)
    ts_v = time.time()

    req_auth = {
        "cert_vj": cert_vj,
        "ek_vj": ek_vj,
        "auth_ref": auth_ref,
        "n_v": n_v,
        "ts_v": ts_v,
        "scope_j": VERIFIER_SCOPE,
    }
    req_auth_bytes = pc.canonical_json_bytes(req_auth)
    h_req_auth = cp.hash_bytes(req_auth_bytes)

    with oqs.Signature(ml_dsa_alg, sk_vj) as signer:
        sigma_vj = signer.sign(h_req_auth)

    print(f"Formed and signed ReqAuth ({len(req_auth_bytes)} bytes, "
          f"signature over H(ReqAuth) per Algorithm 5).")

    outgoing_path = os.path.join(OUT_DIR, "verifier_reqauth.json")
    pc.write_message(outgoing_path, {
        "req_auth": req_auth,
        "sigma_vj": sigma_vj,
    })
    print(f"\nWrote ReqAuth: {outgoing_path}")

    # dk_Vj and the exact req_auth_bytes stay local, needed to process the
    # UAV's response later
    pending_path = os.path.join(OUT_DIR, "verifier_session_pending_DO_NOT_SHARE.json")
    pc.write_message(pending_path, {
        "dk_vj": dk_vj,
        "n_v": n_v,
        "ts_v": ts_v,
        "req_auth_bytes": req_auth_bytes,
        "auth_ref": auth_ref,
    })
    print(f"Wrote session pending state (do not copy): {pending_path}")

    print(f"\nNext step: copy {os.path.basename(outgoing_path)} to the "
          f"Pi's pi_side/in/ directory, then run "
          f"uav_phase4_session_and_respond.py there.")


if __name__ == "__main__":
    main()
