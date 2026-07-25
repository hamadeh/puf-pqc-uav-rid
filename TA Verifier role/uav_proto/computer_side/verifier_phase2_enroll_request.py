"""Create the verifier's TA-challenged enrollment request and PoP."""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import oqs

import protocol_common as pc
import protocol_messages as pm

OUT_DIR = os.path.join(os.path.dirname(__file__), "out")
VERIFIER_ID = "VERIFIER-001"
VERIFIER_ORG = "Test Ground Control Station"
VERIFIER_ROLE = "GCS"
VERIFIER_SCOPE = "test-deployment"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    challenge_path = os.path.join(OUT_DIR, "ta_verifier_challenge.json")
    request_path = os.path.join(OUT_DIR, "verifier_enroll_request.json")
    secret_path = os.path.join(OUT_DIR, "verifier_secret_DO_NOT_SHARE.json")
    if not os.path.exists(challenge_path):
        raise SystemExit(
            "Run ta_phase2_verifier_enroll_process.py --issue-challenge first."
        )
    if any(os.path.exists(path) for path in (request_path, secret_path)) and not args.force:
        raise SystemExit("Refusing to overwrite verifier state; rerun with --force.")
    challenge = pc.read_message(challenge_path)
    if challenge["verifier_id"] != VERIFIER_ID:
        raise ValueError("TA challenge was issued to another verifier")
    now = int(time.time())
    if challenge["expires"] < now:
        raise ValueError("TA verifier challenge has expired")
    valid_until = now + 365 * 86400
    with oqs.Signature(pc.ML_DSA_ALG) as signer:
        pk_v = signer.generate_keypair()
        sk_v = signer.export_secret_key()
        body = pm.encode_cert_request(
            VERIFIER_ID, VERIFIER_ORG, VERIFIER_ROLE, VERIFIER_SCOPE,
            now - pc.FRESHNESS_TOLERANCE_SECONDS, valid_until,
            pk_v, challenge["n_ta"],
        )
        pop = signer.sign(body)
    pc.write_message(request_path, {"body": body, "pop": pop})
    pc.write_message(secret_path, {
        "sk_vj": sk_v, "pk_vj": pk_v, "vid_j": VERIFIER_ID,
    })
    print(f"Wrote challenged verifier request: {request_path}")
    print(f"Wrote verifier private state (do not copy): {secret_path}")


if __name__ == "__main__":
    main()
