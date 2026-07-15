"""
ta_phase2_verifier_enroll_process.py

Runs on: your computer (TA role).
Implements: Algorithm 2's verifier-enrollment procedure, the TA's half.
Issues Cert_Vj and hands back a scoped slice of the operational database,
AuthDB_Vj, containing only root records whose scope matches what this
verifier is authorized for.

Reads verifier_enroll_request.json directly (same machine as the
verifier scripts, see verifier_phase2_enroll_request.py's docstring for
why no hex-copy step is needed here). Reads ta_operational_db.json,
never touches ta_legal_registration_db.json, that file must never
contribute to what a verifier receives.

Produces: out/verifier_AuthDB.json, this is what the verifier keeps
locally to check proofs in Phase 4. If the verifier is later split onto
a separate machine, this is the file you'd copy there.
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
import protocol_common as pc

import oqs

OUT_DIR = os.path.join(os.path.dirname(__file__), "out")


def main():
    request_path = os.path.join(OUT_DIR, "verifier_enroll_request.json")
    secret_path = os.path.join(OUT_DIR, "ta_secret_DO_NOT_SHARE.json")
    ta_public_path = os.path.join(OUT_DIR, "ta_public_params.json")
    operational_db_path = os.path.join(OUT_DIR, "ta_operational_db.json")

    for p in (request_path, secret_path, ta_public_path):
        if not os.path.exists(p):
            print(f"ERROR: {p} not found.")
            sys.exit(1)

    request = pc.read_message(request_path)
    ta_secret = pc.read_message(secret_path)
    ta_public = pc.read_message(ta_public_path)
    sk_ta = ta_secret["sk_ta"]
    ml_dsa_alg = ta_public["ml_dsa_alg"]

    print("Phase 2: Verifier Enrollment, TA side")
    print(f"Processing enrollment request from {request['vid_j']} "
          f"(scope: {request['scope_j']})...")

    # Cert_Vj = Sign_SK_TA(VID_j || PK_Vj || Scope_j || Validity_j)
    # Canonical JSON for validity_j, same reasoning as the AuthRec fix in
    # ta_phase2_enroll_process.py, str(dict) is not safe to rely on here.
    validity_canonical = json.dumps(request["validity_j"], sort_keys=True).encode("utf-8")
    to_sign = (
        request["vid_j"].encode("utf-8") + request["pk_vj"] +
        request["scope_j"].encode("utf-8") + validity_canonical
    )
    with oqs.Signature(ml_dsa_alg, sk_ta) as ta_signer:
        cert_signature = ta_signer.sign(to_sign)

    print(f"  Issued Cert_Vj: {len(cert_signature)} bytes")

    # Build the scoped AuthDB_Vj: only root records matching this verifier's scope
    operational_db = pc.read_message(operational_db_path) if os.path.exists(operational_db_path) \
        else {"root_records": []}

    scoped_records = [
        r for r in operational_db["root_records"]
        if r["flight_ctx"].get("scope") == request["scope_j"]
    ]
    print(f"  AuthDB_Vj: {len(scoped_records)} of "
          f"{len(operational_db['root_records'])} root records match scope "
          f"'{request['scope_j']}'")

    auth_db = {
        "vid_j": request["vid_j"],
        "cert_vj": {
            "vid_j": request["vid_j"],
            "pk_vj": request["pk_vj"],
            "scope_j": request["scope_j"],
            "validity_j": request["validity_j"],
            "signature": cert_signature,
        },
        "root_records": scoped_records,
    }

    auth_db_path = os.path.join(OUT_DIR, "verifier_AuthDB.json")
    pc.write_message(auth_db_path, auth_db)
    print(f"\nWrote AuthDB_Vj: {auth_db_path}")
    print("(same machine as the verifier scripts here; copy this file "
          "elsewhere only if you later run the verifier on a separate machine)")


if __name__ == "__main__":
    main()
