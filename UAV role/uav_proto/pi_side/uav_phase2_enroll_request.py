"""Create initial-enrollment or renewal root requests with UAV PoP."""

import argparse
import os
import secrets
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import oqs

import crypto_primitives as cp
import fuzzy_extractor
import merkle
import protocol_common as pc
import protocol_messages as pm
import puf_emulated
import seeded_ml_dsa

BASE = os.path.dirname(__file__)
IN_DIR = os.path.join(BASE, "in")
OUT_DIR = os.path.join(BASE, "out")
UAV_ID = "uav-001"
UAV_CTX = b"uav-001"


def _root(S2: bytes, root_nonce: bytes, ctx_wire: bytes) -> tuple[bytes, list]:
    ctx = pm.decode_flight_ctx(ctx_wire)
    seed_k = pc.kdf_labeled(
        pc.TAG_MERKLE_ROOT, S2, root_nonce, pc.u32(ctx["k"])
    )
    leaves = []
    for j in range(1, ctx["n"] + 1):
        x_kj = pc.kdf_labeled(pc.TAG_INTERVAL_SECRET, seed_k, pc.u32(j))
        pid = pc.hash_labeled(
            pc.TAG_RID, x_kj, pc.u32(j), root_nonce, ctx_wire
        )[:16]
        leaves.append(merkle.leaf_hash(pid, j, root_nonce, ctx_wire))
    levels = merkle.build_tree(leaves)
    return merkle.root(levels), levels


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--renew", action="store_true")
    parser.add_argument("--new-emulated-device", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    params_path = os.path.join(IN_DIR, "ta_public_params.json")
    challenge_path = os.path.join(IN_DIR, "ta_uav_root_challenges.json")
    store_path = os.path.join(OUT_DIR, "uav_store_nv.json")
    pending_path = os.path.join(OUT_DIR, "uav_local_pending_DO_NOT_SHARE.json")
    outgoing_path = os.path.join(OUT_DIR, "uav_root_requests.json")
    for path in (params_path, challenge_path):
        if not os.path.exists(path):
            raise SystemExit(f"Missing {path}")
    existing_outputs = [
        path for path in (pending_path, outgoing_path) if os.path.exists(path)
    ]
    if existing_outputs and not args.force:
        raise SystemExit(
            "Refusing to overwrite existing enrollment output; use --force "
            "after preserving it."
        )
    if args.new_emulated_device:
        if args.renew:
            parser.error("--new-emulated-device cannot be used for renewal")
        puf_emulated.reset_store()

    params = pc.read_message(params_path)
    challenges = pc.read_message(challenge_path)
    if challenges["uav_id"] != UAV_ID:
        raise SystemExit("TA challenge is for a different UAV")

    if args.renew:
        if not os.path.exists(store_path):
            raise SystemExit("--renew requires an existing uav_store_nv.json")
        old_store = pc.read_message(store_path)
        c_seed = old_store["c_seed"]
        helper = old_store["helper_data"]
        k_puf = fuzzy_extractor.rec_from_seed(c_seed, helper)
        if k_puf is None:
            raise SystemExit("PUF reconstruction failed")
        expected_kc = old_store["kc_i"]
    else:
        if os.path.exists(store_path) and not args.force:
            raise SystemExit(
                "Existing enrollment found; use --renew or explicitly --force."
            )
        c_seed = secrets.token_bytes(32)
        k_puf, helper = fuzzy_extractor.gen_from_seed(c_seed)
        expected_kc = None

    S1, S2 = pc.derive_purpose_secrets(k_puf, UAV_CTX)
    pk_i, sk_i = seeded_ml_dsa.seeded_keygen(params["ml_dsa_alg"], S1)
    kc_i = cp.hash_bytes(pk_i)
    if expected_kc is not None and kc_i != expected_kc:
        raise SystemExit("renewal key-confirmation check failed")

    request_items = []
    pending_roots = []
    with oqs.Signature(params["ml_dsa_alg"], sk_i) as signer:
        for challenge in challenges["challenges"]:
            ctx_wire = challenge["flight_ctx_wire"]
            ctx = pm.decode_flight_ctx(ctx_wire)
            if ctx["n"] != params["n_intervals"]:
                raise ValueError("TA challenge n disagrees with public parameters")
            while True:
                root_nonce = secrets.token_bytes(16)
                mr_k, _ = _root(S2, root_nonce, ctx_wire)
                if all(r["mr_k"] != mr_k for r in pending_roots):
                    break
            body = pm.encode_root_request(
                pk_i, mr_k, root_nonce, ctx_wire, challenge["n_ta"]
            )
            request_items.append({"body": body, "pop": signer.sign(body)})
            pending_roots.append({
                "mr_k": mr_k, "root_nonce": root_nonce,
                "flight_ctx_wire": ctx_wire,
            })
            print(f"Prepared k={ctx['k']}, n={ctx['n']}, root={mr_k.hex()[:16]}...")

    pc.write_message(outgoing_path, {
        "protocol_version": pc.PROTOCOL_VERSION,
        "uav_id": UAV_ID, "requests": request_items,
    })
    # No SK_i, K_PUF, S1, S2, Seed_k, or interval secrets are persisted.
    pc.write_message(pending_path, {
        "renewal": args.renew,
        "replace_existing": bool(args.force and not args.renew),
        "c_seed": c_seed, "helper_data": helper,
        "kc_i": kc_i, "pk_i": pk_i, "roots": pending_roots,
    })
    print(f"Wrote requests: {outgoing_path}")
    print(f"Wrote non-secret finalize state: {pending_path}")


if __name__ == "__main__":
    main()
