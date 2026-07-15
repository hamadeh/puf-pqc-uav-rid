"""
verifier_phase2_enroll_request.py

Runs on: your computer (Verifier role, V_j). Logically a separate
security domain from the TA even though both happen to run on the same
physical machine here, this script keeps SK_Vj local to itself and never
shares it, including with the TA script, the same way it wouldn't if
this were a separate machine.

Implements: Algorithm 2's verifier-enrollment procedure, the verifier's
half. Generates the verifier's own ML-DSA key pair and writes the
enrollment request.

Produces: out/verifier_enroll_request.json. If you're running this on
the same machine as the TA scripts, just point the TA script's in/ at
this file directly; there's no real reason to hex-encode-and-copy when
both roles share a filesystem, but I'm keeping the same file-message
convention throughout so the code stays identical to what you'd need if
you later split the verifier onto a separate machine too.
"""

import sys
import os
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
import protocol_common as pc

import oqs

OUT_DIR = os.path.join(os.path.dirname(__file__), "out")

VERIFIER_ID = "VERIFIER-001"
VERIFIER_ORG = "Test Ground Control Station"
VERIFIER_ROLE = "GCS"
VERIFIER_SCOPE = "test-deployment"  # must match the UAV's flight_ctx scope to be useful later


def main():
    ta_params_path = os.path.join(OUT_DIR, "ta_public_params.json")
    if not os.path.exists(ta_params_path):
        print(f"ERROR: {ta_params_path} not found. Run ta_phase1_init.py first.")
        sys.exit(1)

    ta_params = pc.read_message(ta_params_path)
    ml_dsa_alg = ta_params["ml_dsa_alg"]

    print("Phase 2: Verifier Enrollment, verifier side")
    print(f"Generating {ml_dsa_alg} key pair for verifier {VERIFIER_ID}...")

    with oqs.Signature(ml_dsa_alg) as signer:
        pk_vj = signer.generate_keypair()
        sk_vj = signer.export_secret_key()

    print(f"  PK_Vj: {len(pk_vj)} bytes")

    request = {
        "vid_j": VERIFIER_ID,
        "org_j": VERIFIER_ORG,
        "role_j": VERIFIER_ROLE,
        "scope_j": VERIFIER_SCOPE,
        "validity_j": {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T23:59:59Z"},
        "pk_vj": pk_vj,
    }
    request_path = os.path.join(OUT_DIR, "verifier_enroll_request.json")
    pc.write_message(request_path, request)
    print(f"\nWrote enrollment request: {request_path}")

    # SK_Vj stays with the verifier, only ever in this file, never sent anywhere
    secret_path = os.path.join(OUT_DIR, "verifier_secret_DO_NOT_SHARE.json")
    pc.write_message(secret_path, {"sk_vj": sk_vj, "vid_j": VERIFIER_ID})
    print(f"Wrote verifier secret key (DO NOT COPY THIS FILE): {secret_path}")

    print(f"\nNext step: run ta_phase2_verifier_enroll_process.py "
          f"(reads {os.path.basename(request_path)} directly, same machine).")


if __name__ == "__main__":
    main()
