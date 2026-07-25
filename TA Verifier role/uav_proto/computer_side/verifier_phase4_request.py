"""Build and directly sign the canonical Algorithm-5 verifier request."""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import oqs

import protocol_common as pc
import protocol_messages as pm
import revocation

BASE = os.path.dirname(__file__)
IN_DIR = os.path.join(BASE, "in")
OUT_DIR = os.path.join(BASE, "out")
EXPECTED_SCOPE = "test-deployment"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    request_path = os.path.join(OUT_DIR, "verifier_reqauth.bin")
    pending_path = os.path.join(
        OUT_DIR, "verifier_session_pending_DO_NOT_SHARE.json"
    )
    if any(os.path.exists(path) for path in (request_path, pending_path)) and not args.force:
        raise SystemExit("Refusing to overwrite session files; rerun with --force.")
    with open(os.path.join(IN_DIR, "broadcast_log.jsonl"), encoding="utf-8") as handle:
        lines = [line for line in handle if line.strip()]
    if not lines:
        raise SystemExit("No captured broadcast")
    capture = json.loads(lines[-1])
    auth_ref = bytes.fromhex(capture["pid"])
    if len(auth_ref) != 16:
        raise ValueError("captured Profile-P pseudonym is not 16 bytes")
    capture_time = int(capture["timestamp"])

    params = pc.read_message(os.path.join(OUT_DIR, "ta_public_params.json"))
    auth_db = pc.read_message(os.path.join(OUT_DIR, "verifier_AuthDB.json"))
    secret = pc.read_message(
        os.path.join(OUT_DIR, "verifier_secret_DO_NOT_SHARE.json")
    )
    rl = revocation.verify_record(
        auth_db["rl_record"], params["pk_ta"]
    )
    cert_body, cert_sig = pm.decode_signed_record(
        auth_db["cert_record"], pm.TYPE_CERT_RECORD
    )
    cert = pm.decode_cert_body(cert_body)
    with oqs.Signature(params["ml_dsa_alg"]) as verifier:
        if not verifier.verify(cert_body, cert_sig, params["pk_ta"]):
            raise ValueError("invalid TA verifier certificate")
    revocation.assert_not_revoked(
        rl, cert_id=revocation.object_id(auth_db["cert_record"])
    )
    now = int(time.time())
    if abs(now - capture_time) > params["freshness_tolerance_seconds"]:
        raise ValueError(
            "captured broadcast is too old; capture a fresh UAS ID before "
            "creating the verifier request"
        )
    if not cert["valid_from"] <= now <= cert["valid_until"]:
        raise ValueError("verifier certificate outside validity")
    if cert["scope"] != EXPECTED_SCOPE:
        raise ValueError("verifier certificate scope mismatch")

    with oqs.KeyEncapsulation(params["ml_kem_alg"]) as kem:
        ek_v = kem.generate_keypair()
        dk_v = kem.export_secret_key()
    n_v = os.urandom(16)
    req_wire = pm.encode_verifier_request(
        auth_db["cert_record"], ek_v, auth_ref, n_v, capture_time,
        EXPECTED_SCOPE, rl["version"],
    )
    with oqs.Signature(params["ml_dsa_alg"], secret["sk_vj"]) as signer:
        signed_wire = pm.encode_signed_request(req_wire, signer.sign(req_wire))
    with open(request_path, "wb") as handle:
        handle.write(signed_wire)
    pc.write_message(pending_path, {
        "dk_vj": dk_v, "req_wire": req_wire, "auth_ref": auth_ref,
        "n_v": n_v, "ts_v": capture_time,
        "requested_scope": EXPECTED_SCOPE,
    })
    print(f"Wrote canonical request ({len(signed_wire)} bytes): {request_path}")


if __name__ == "__main__":
    main()
