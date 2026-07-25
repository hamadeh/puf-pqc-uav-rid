"""Issue UAV root challenges or authorize proof-of-possession root requests."""

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

BASE = os.path.dirname(__file__)
IN_DIR = os.path.join(BASE, "in")
OUT_DIR = os.path.join(BASE, "out")


def _load(name: str, default):
    path = os.path.join(OUT_DIR, name)
    return pc.read_message(path) if os.path.exists(path) else default


def _save(name: str, value) -> None:
    pc.write_message(os.path.join(OUT_DIR, name), value)


def issue_challenges(args, public: dict, secret: dict) -> None:
    path = os.path.join(OUT_DIR, "ta_uav_root_challenges.json")
    if os.path.exists(path) and not args.force:
        raise SystemExit(f"Refusing to overwrite {path}; rerun with --force.")
    device = next(
        (entry for entry in secret["device_registry"]
         if entry["uav_id"] == args.uav_id and entry["status"] == "authorized"),
        None,
    )
    if device is None:
        raise SystemExit("UAV is not an authorized TA device record")
    operational = _load("ta_operational_db.json", {"root_records": []})
    existing_contexts = [
        pm.decode_root_auth_body(
            pm.decode_signed_record(r["auth_record"], pm.TYPE_AUTH_RECORD)[0]
        )["flight_ctx"]
        for r in operational["root_records"]
        if r.get("uav_id") == args.uav_id
    ]
    used = {ctx["k"] for ctx in existing_contexts}
    next_k = max(used, default=-1) + 1
    now = int(time.time())
    earliest_nonoverlap = max(
        [now] + [ctx["end_time"] + 1 for ctx in existing_contexts]
    )
    start = (
        args.start_time
        if args.start_time is not None else earliest_nonoverlap
    )
    if start < earliest_nonoverlap:
        raise ValueError("requested root window overlaps an authorized window")
    challenges = []
    for offset in range(public["m_roots"]):
        k = next_k + offset
        ctx = {
            "k": k,
            "delta_t": public["delta_t_seconds"],
            "n": public["n_intervals"],
            "start_time": start + offset * public["n_intervals"]
            * public["delta_t_seconds"],
            "end_time": start + (offset + 1) * public["n_intervals"]
            * public["delta_t_seconds"] - 1,
            "region": args.region,
            "scope": args.scope,
        }
        challenge = {
            "uav_id": args.uav_id, "n_ta": secrets.token_bytes(16),
            "flight_ctx_wire": pm.encode_flight_ctx(ctx),
            "expires": now + 900, "used": False,
        }
        challenges.append(challenge)
        secret["issued_uav_challenges"].append(challenge)
    _save("ta_secret_DO_NOT_SHARE.json", secret)
    pc.write_message(path, {
        "uav_id": args.uav_id,
        "challenges": [{
            "n_ta": c["n_ta"], "flight_ctx_wire": c["flight_ctx_wire"],
            "expires": c["expires"],
        } for c in challenges],
    })
    print(f"Issued {len(challenges)} fresh root challenge(s): {path}")


def process_requests(public: dict, secret: dict, force: bool) -> None:
    request_path = os.path.join(IN_DIR, "uav_root_requests.json")
    response_path = os.path.join(OUT_DIR, "ta_authrec_response.json")
    if not os.path.exists(request_path):
        raise SystemExit(f"Missing {request_path}")
    if os.path.exists(response_path) and not force:
        raise SystemExit(f"Refusing to overwrite {response_path}; use --force.")
    incoming = pc.read_message(request_path)
    uav_id = incoming.get("uav_id")
    device = next(
        (entry for entry in secret["device_registry"]
         if entry["uav_id"] == uav_id and entry["status"] == "authorized"),
        None,
    )
    if device is None:
        raise SystemExit("No authenticated, authorized TA device record")

    operational = _load("ta_operational_db.json", {"root_records": []})
    legal = _load("ta_legal_registration_db.json", {
        "device_bindings": [], "root_to_legal_id": [],
    })
    existing_k = set()
    for record in operational["root_records"]:
        if record.get("uav_id") != uav_id:
            continue
        body, _ = pm.decode_signed_record(
            record["auth_record"], pm.TYPE_AUTH_RECORD
        )
        existing_k.add(pm.decode_root_auth_body(body)["flight_ctx"]["k"])

    now = int(time.time())
    accepted = []
    first_pk = None
    with oqs.Signature(public["ml_dsa_alg"]) as verifier, \
            oqs.Signature(public["ml_dsa_alg"], secret["sk_ta"]) as signer:
        for item in incoming.get("requests", []):
            body = item["body"]
            pop = item["pop"]
            req = pm.decode_root_request(body)
            ctx = req["flight_ctx"]
            if ctx["n"] != public["n_intervals"] or ctx["delta_t"] != public["delta_t_seconds"]:
                raise ValueError("root request uses unauthorized public parameters")
            if ctx["k"] in existing_k:
                raise ValueError(f"root index k={ctx['k']} was already authorized")
            challenge = next(
                (c for c in secret["issued_uav_challenges"]
                 if c["uav_id"] == uav_id and c["n_ta"] == req["n_ta"]
                 and c["flight_ctx_wire"] == req["flight_ctx_wire"]),
                None,
            )
            if challenge is None or challenge["used"] or challenge["expires"] < now:
                raise ValueError("missing, expired, reused, or mismatched TA challenge")
            if not verifier.verify(body, pop, req["pk_i"]):
                raise ValueError("invalid UAV proof of possession")
            if device["bound_pk_i"] is not None and device["bound_pk_i"] != req["pk_i"]:
                raise ValueError("renewal attempted with a different UAV key")
            if first_pk is not None and first_pk != req["pk_i"]:
                raise ValueError("batch contains more than one UAV key")
            first_pk = req["pk_i"]
            auth_body = pm.encode_root_auth_body(
                req["pk_i"], req["mr_k"], req["root_nonce"],
                req["flight_ctx_wire"],
            )
            auth_record = pm.encode_signed_record(
                auth_body, signer.sign(auth_body), pm.TYPE_AUTH_RECORD
            )
            root_id = revocation.object_id(auth_record)
            key_identifier = revocation.key_id(req["pk_i"])
            accepted.append({
                "auth_record": auth_record, "root_id": root_id,
                "key_id": key_identifier,
            })
            operational["root_records"].append({
                **accepted[-1], "uav_id": uav_id,
            })
            legal["root_to_legal_id"].append({
                "root_id": root_id, "legal_id": device["legal_id"],
            })
            challenge["used"] = True
            existing_k.add(ctx["k"])

    if not accepted:
        raise SystemExit("No valid root requests were supplied")
    # The legal key binding is committed only after at least one valid PoP.
    if device["bound_pk_i"] is None:
        device["bound_pk_i"] = first_pk
        legal["device_bindings"].append({
            "key_id": revocation.key_id(first_pk),
            "legal_id": device["legal_id"],
        })
    _save("ta_secret_DO_NOT_SHARE.json", secret)
    _save("ta_operational_db.json", operational)
    _save("ta_legal_registration_db.json", legal)
    pc.write_message(response_path, {"auth_records": accepted})
    print(f"Authorized {len(accepted)} root(s): {response_path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issue-challenges", action="store_true")
    parser.add_argument("--uav-id", default="uav-001")
    parser.add_argument("--scope", default="test-deployment")
    parser.add_argument("--region", default="TEST-REGION")
    parser.add_argument("--start-time", type=int)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    public = pc.read_message(os.path.join(OUT_DIR, "ta_public_params.json"))
    secret = pc.read_message(os.path.join(OUT_DIR, "ta_secret_DO_NOT_SHARE.json"))
    if args.issue_challenges:
        issue_challenges(args, public, secret)
    else:
        process_requests(public, secret, args.force)


if __name__ == "__main__":
    main()
