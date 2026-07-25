"""Verify TA root records and commit the UAV's nonvolatile enrollment state."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import oqs

import protocol_common as pc
import protocol_messages as pm
import revocation

BASE = os.path.dirname(__file__)
IN_DIR = os.path.join(BASE, "in")
OUT_DIR = os.path.join(BASE, "out")


def main() -> None:
    response_path = os.path.join(IN_DIR, "ta_authrec_response.json")
    params_path = os.path.join(IN_DIR, "ta_public_params.json")
    rl_path = os.path.join(IN_DIR, "ta_revocation_list.json")
    pending_path = os.path.join(OUT_DIR, "uav_local_pending_DO_NOT_SHARE.json")
    for path in (response_path, params_path, rl_path, pending_path):
        if not os.path.exists(path):
            raise SystemExit(f"Missing {path}")
    response = pc.read_message(response_path)
    params = pc.read_message(params_path)
    pending = pc.read_message(pending_path)
    rl_record = pc.read_message(rl_path)["rl_record"]
    rl = revocation.verify_record(rl_record, params["pk_ta"])

    pending_by_body = {
        pm.encode_root_auth_body(
            pending["pk_i"], root["mr_k"], root["root_nonce"],
            root["flight_ctx_wire"],
        ): root
        for root in pending["roots"]
    }
    accepted = []
    with oqs.Signature(params["ml_dsa_alg"]) as verifier:
        for item in response.get("auth_records", []):
            record = item["auth_record"]
            body, signature = pm.decode_signed_record(
                record, pm.TYPE_AUTH_RECORD
            )
            root = pending_by_body.get(body)
            if root is None:
                raise ValueError("TA returned a root record not requested by this UAV")
            if not verifier.verify(body, signature, params["pk_ta"]):
                raise ValueError("invalid TA root-record signature")
            parsed = pm.decode_root_auth_body(body)
            root_id = revocation.object_id(record)
            key_identifier = revocation.key_id(parsed["pk_i"])
            revocation.assert_not_revoked(
                rl, root_id=root_id, key_id_value=key_identifier
            )
            accepted.append({
                "auth_record": record, "root_id": root_id,
                "key_id": key_identifier,
            })
    if len(accepted) != len(pending["roots"]):
        raise SystemExit("TA response did not authorize every pending root")

    store_path = os.path.join(OUT_DIR, "uav_store_nv.json")
    prior_roots = []
    if pending["renewal"]:
        prior = pc.read_message(store_path)
        if prior["kc_i"] != pending["kc_i"]:
            raise ValueError("renewal changed KC_i")
        prior_roots = prior["roots"]
    elif os.path.exists(store_path) and not pending.get("replace_existing", False):
        raise SystemExit(
            "Refusing to overwrite existing UAV enrollment without prior "
            "--force authorization."
        )
    all_roots = prior_roots + accepted
    if len({record["root_id"] for record in all_roots}) != len(all_roots):
        raise ValueError("duplicate authorized root")
    pc.write_message(store_path, {
        "protocol_version": pc.PROTOCOL_VERSION,
        "c_seed": pending["c_seed"],
        "helper_data": pending["helper_data"],
        "kc_i": pending["kc_i"],
        "pk_i": pending["pk_i"],
        "rl_record": rl_record,
        "highest_rl_version": rl["version"],
        "roots": all_roots,
    })
    os.remove(pending_path)
    print(f"Stored {len(all_roots)} authorized root(s): {store_path}")
    print("No per-interval journal is used; j is derived from trusted time.")


if __name__ == "__main__":
    main()
