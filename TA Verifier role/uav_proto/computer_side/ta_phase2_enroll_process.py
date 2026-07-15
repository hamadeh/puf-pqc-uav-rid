"""
ta_phase2_enroll_process.py

Runs on: your computer (TA role).
Implements: Algorithm 1, the TA-side steps, verify RootReq_i^(k), register
PK_i, sign AuthRec_i^(k) (Eq. root_authorization_record), and record the
legal traceability mapping MR_i^(k) -> ID_i.

BEFORE RUNNING: copy uav_root_requests.json from the Pi's pi_side/out/
into this script's in/ directory.

Produces: out/ta_authrec_response.json, copy this back to the Pi's
pi_side/in/ directory, then run uav_phase2_enroll_finalize.py there.

Maintains TWO SEPARATE local databases, matching the paper's explicit
requirement (Section III.A) that these stay logically separated so
operator identity never reaches a verifier:

  out/ta_legal_registration_db.json
      MR_i^(k) -> real legal ID mapping. Stays on this machine, full
      stop. Never read by verifier_phase2_enroll scripts, never copied
      anywhere. If you ever wire up lawful-traceability logic, this is
      the only file it should touch.

  out/ta_operational_db.json
      PK_i, MR_i^(k), RootNonce_k, FlightCtx_k, AuthRec_i^(k), no legal
      ID anywhere in it. This is the file ta_phase2_verifier_enroll_
      process.py reads from to build a verifier's scoped AuthDB_Vj.

PROTOTYPE SIMPLIFICATION: this script accepts any incoming RootReq
without a prior out-of-band registration/authorization check (your paper
describes the TA reviewing an operator's registration and flight
authorization before this point). Real deployment logic (identity
vetting, flight-authorization approval) is out of scope here; this script
only implements the cryptographic verify-and-sign step.
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
import protocol_common as pc

import oqs

IN_DIR = os.path.join(os.path.dirname(__file__), "in")
OUT_DIR = os.path.join(os.path.dirname(__file__), "out")

UAV_LEGAL_ID = "UAV-LEGAL-ID-001"  # stand-in for the TA's real identity vetting


def load_db(filename, default):
    path = os.path.join(OUT_DIR, filename)
    if os.path.exists(path):
        return pc.read_message(path)
    return default


def save_db(filename, db):
    path = os.path.join(OUT_DIR, filename)
    pc.write_message(path, db)


def main():
    incoming_path = os.path.join(IN_DIR, "uav_root_requests.json")
    secret_path = os.path.join(OUT_DIR, "ta_secret_DO_NOT_SHARE.json")

    if not os.path.exists(incoming_path):
        print(f"ERROR: {incoming_path} not found.")
        print("Copy uav_root_requests.json from the Pi's pi_side/out/ "
              "into this script's in/ directory first.")
        sys.exit(1)
    if not os.path.exists(secret_path):
        print(f"ERROR: {secret_path} not found. Run ta_phase1_init.py first.")
        sys.exit(1)

    request_msg = pc.read_message(incoming_path)
    ta_secret = pc.read_message(secret_path)
    sk_ta = ta_secret["sk_ta"]

    # ml_dsa_alg isn't in the request; re-derive it the same way Phase 1 did
    ta_public_path = os.path.join(OUT_DIR, "ta_public_params.json")
    ta_public = pc.read_message(ta_public_path)
    ml_dsa_alg = ta_public["ml_dsa_alg"]

    print(f"Phase 2: UAV Enrollment (Algorithm 1), TA side")
    print(f"Processing {len(request_msg['requests'])} root requests from UAV...")

    legal_db = load_db("ta_legal_registration_db.json", {"registered_pks": [], "mr_to_id": []})
    operational_db = load_db("ta_operational_db.json", {"root_records": []})

    auth_recs = []
    with oqs.Signature(ml_dsa_alg, sk_ta) as ta_signer:
        pk_i_registered = False

        for req in request_msg["requests"]:
            k = req["k"]
            pk_i = req["pk_i"]
            mr_k = req["mr_k"]
            root_nonce = req["root_nonce"]
            flight_ctx = req["flight_ctx"]

            if not pk_i_registered:
                legal_db["registered_pks"].append({"pk_i": pk_i, "legal_id": UAV_LEGAL_ID})
                pk_i_registered = True
                print(f"  Registered PK_i ({len(pk_i)} bytes) under legal ID "
                      f"{UAV_LEGAL_ID} in legal registration database.")

            # AuthRec_i^(k) = Sign_SK_TA(PK_i || MR_i^(k) || RootNonce_k ||
            #                            FlightCtx_k || Validity_k || Scope_k)
            # flight_ctx already bundles validity/scope for this prototype.
            # Canonical JSON (sort_keys=True) so the UAV can reconstruct this
            # exact byte string later from its own local flight_ctx and
            # verify the signature; str(dict) would NOT be safe here, key
            # ordering isn't guaranteed to round-trip identically otherwise.
            flight_ctx_canonical = json.dumps(flight_ctx, sort_keys=True).encode("utf-8")
            to_sign = pk_i + mr_k + root_nonce + flight_ctx_canonical
            signature = ta_signer.sign(to_sign)

            auth_recs.append({
                "k": k,
                "signature": signature,
            })

            # Legal DB: traceability mapping only (MR -> real identity)
            legal_db["mr_to_id"].append({"mr_k": mr_k, "legal_id": UAV_LEGAL_ID, "k": k})

            # Operational DB: everything a verifier is allowed to see,
            # deliberately no legal_id anywhere in this record
            operational_db["root_records"].append({
                "mr_k": mr_k,
                "k": k,
                "pk_i": pk_i,
                "root_nonce": root_nonce,
                "flight_ctx": flight_ctx,
                "auth_rec_signature": signature,
            })
            print(f"  Signed AuthRec_i^(k={k}): MR = {mr_k.hex()[:16]}..., "
                  f"signature = {len(signature)} bytes")

    save_db("ta_legal_registration_db.json", legal_db)
    save_db("ta_operational_db.json", operational_db)

    response_path = os.path.join(OUT_DIR, "ta_authrec_response.json")
    pc.write_message(response_path, {"auth_recs": auth_recs})
    print(f"\nWrote AuthRec response: {response_path}")
    print("Updated ta_legal_registration_db.json and ta_operational_db.json "
          "(both stay on this machine).")
    print(f"\nNext step: copy {os.path.basename(response_path)} to the "
          f"Pi's pi_side/in/ directory, then run "
          f"uav_phase2_enroll_finalize.py there.")


if __name__ == "__main__":
    main()
