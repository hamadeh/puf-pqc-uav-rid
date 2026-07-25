"""Issue a verifier challenge or validate PoP and return a scoped AuthDB."""

import argparse
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import oqs

import protocol_common as pc
import protocol_messages as pm
import revocation

OUT_DIR = os.path.join(os.path.dirname(__file__), "out")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issue-challenge", action="store_true")
    parser.add_argument("--verifier-id", default="VERIFIER-001")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    secret_path = os.path.join(OUT_DIR, "ta_secret_DO_NOT_SHARE.json")
    public_path = os.path.join(OUT_DIR, "ta_public_params.json")
    secret = pc.read_message(secret_path)
    public = pc.read_message(public_path)

    if args.issue_challenge:
        path = os.path.join(OUT_DIR, "ta_verifier_challenge.json")
        if os.path.exists(path) and not args.force:
            raise SystemExit(f"Refusing to overwrite {path}; use --force.")
        challenge = {
            "verifier_id": args.verifier_id,
            "n_ta": secrets.token_bytes(16),
            "expires": int(time.time()) + 900,
            "used": False,
        }
        secret["issued_verifier_challenges"].append(challenge)
        pc.write_message(secret_path, secret)
        pc.write_message(path, {
            "verifier_id": challenge["verifier_id"],
            "n_ta": challenge["n_ta"], "expires": challenge["expires"],
        })
        print(f"Issued verifier challenge: {path}")
        return

    request_path = os.path.join(OUT_DIR, "verifier_enroll_request.json")
    auth_db_path = os.path.join(OUT_DIR, "verifier_AuthDB.json")
    if os.path.exists(auth_db_path) and not args.force:
        raise SystemExit(f"Refusing to overwrite {auth_db_path}; use --force.")
    request = pc.read_message(request_path)
    body, pop = request["body"], request["pop"]
    parsed = pm.decode_cert_request(body)
    now = int(time.time())
    challenge = next(
        (entry for entry in secret["issued_verifier_challenges"]
         if entry["verifier_id"] == parsed["verifier_id"]
         and entry["n_ta"] == parsed["n_ta"]),
        None,
    )
    if challenge is None or challenge["used"] or challenge["expires"] < now:
        raise ValueError("missing, expired, or reused verifier challenge")
    if parsed["valid_from"] > now + pc.FRESHNESS_TOLERANCE_SECONDS:
        raise ValueError("verifier certificate is not yet valid")
    with oqs.Signature(public["ml_dsa_alg"]) as verifier:
        if not verifier.verify(body, pop, parsed["pk_v"]):
            raise ValueError("invalid verifier proof of possession")
    cert_body = pm.encode_cert_body(
        parsed["verifier_id"], parsed["organization"], parsed["role"],
        parsed["scope"], parsed["valid_from"], parsed["valid_until"],
        parsed["pk_v"],
    )
    with oqs.Signature(public["ml_dsa_alg"], secret["sk_ta"]) as signer:
        cert_record = pm.encode_signed_record(
            cert_body, signer.sign(cert_body), pm.TYPE_CERT_RECORD
        )
    challenge["used"] = True
    pc.write_message(secret_path, secret)

    operational_path = os.path.join(OUT_DIR, "ta_operational_db.json")
    operational = (
        pc.read_message(operational_path)
        if os.path.exists(operational_path) else {"root_records": []}
    )
    scoped = []
    for record in operational["root_records"]:
        auth_body, _ = pm.decode_signed_record(
            record["auth_record"], pm.TYPE_AUTH_RECORD
        )
        if pm.decode_root_auth_body(auth_body)["flight_ctx"]["scope"] == parsed["scope"]:
            scoped.append({
                "auth_record": record["auth_record"],
                "root_id": record["root_id"], "key_id": record["key_id"],
            })
    rl_record = pc.read_message(
        os.path.join(OUT_DIR, "ta_revocation_list.json")
    )["rl_record"]
    auth_db = {
        "protocol_version": pc.PROTOCOL_VERSION,
        "cert_record": cert_record,
        "cert_id": revocation.object_id(cert_record),
        "root_records": scoped,
        "rl_record": rl_record,
    }
    pc.write_message(auth_db_path, auth_db)
    print(
        f"Issued certificate and {len(scoped)} scoped root record(s): "
        f"{auth_db_path}"
    )


if __name__ == "__main__":
    main()
