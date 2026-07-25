"""TA system initialization for protocol version 1."""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

import oqs

import protocol_common as pc
import protocol_messages as pm

OUT_DIR = os.path.join(os.path.dirname(__file__), "out")


def _refuse_overwrite(paths: list[str], force: bool) -> None:
    existing = [path for path in paths if os.path.exists(path)]
    if existing and not force:
        names = ", ".join(os.path.basename(path) for path in existing)
        raise SystemExit(f"Refusing to overwrite {names}; rerun with --force.")


def main() -> None:
    parser = argparse.ArgumentParser(description="TA system initialization")
    parser.add_argument("--n", type=int, default=pc.N_INTERVALS)
    parser.add_argument("--m", type=int, default=pc.M_ROOTS)
    parser.add_argument("--delta-t", type=int, default=pc.DELTA_T_SECONDS)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if args.n < 1 or args.n & (args.n - 1):
        parser.error("--n must be a positive power of two")
    if args.m < 1:
        parser.error("--m must be positive")
    if args.delta_t < 1:
        parser.error("--delta-t must be positive")

    public_path = os.path.join(OUT_DIR, "ta_public_params.json")
    secret_path = os.path.join(OUT_DIR, "ta_secret_DO_NOT_SHARE.json")
    rl_path = os.path.join(OUT_DIR, "ta_revocation_list.json")
    legal_path = os.path.join(OUT_DIR, "ta_legal_registration_db.json")
    operational_path = os.path.join(OUT_DIR, "ta_operational_db.json")
    _refuse_overwrite(
        [public_path, secret_path, rl_path, legal_path, operational_path],
        args.force,
    )

    with oqs.Signature(pc.ML_DSA_ALG) as signer:
        pk_ta = signer.generate_keypair()
        sk_ta = signer.export_secret_key()
    now = int(time.time())
    rl_body = pm.encode_revocation_body(
        1, now - pc.FRESHNESS_TOLERANCE_SECONDS, now + 365 * 86400,
        [], [], [],
    )
    with oqs.Signature(pc.ML_DSA_ALG, sk_ta) as signer:
        rl_record = pm.encode_signed_record(
            rl_body, signer.sign(rl_body), pm.TYPE_REVOCATION_RECORD
        )

    public = {
        "protocol_version": pc.PROTOCOL_VERSION,
        "pk_ta": pk_ta,
        "ml_dsa_alg": pc.ML_DSA_ALG,
        "ml_kem_alg": pc.ML_KEM_ALG,
        "delta_t_seconds": args.delta_t,
        "n_intervals": args.n,
        "m_roots": args.m,
        "freshness_tolerance_seconds": pc.FRESHNESS_TOLERANCE_SECONDS,
        "max_request_bytes": pc.MAX_REQUEST_BYTES,
        "puf_profile": {
            "comparisons": 1023, "reads": 9, "selected": 950,
            "margin_threshold": 0.005, "bch": "BCH(950,870), t=8",
            "extractor": "Toeplitz-950-to-256",
        },
    }
    secret = {
        "sk_ta": sk_ta,
        "issued_uav_challenges": [],
        "issued_verifier_challenges": [],
        "revocation_version": 1,
        "device_registry": [{
            "uav_id": "uav-001", "legal_id": "UAV-LEGAL-ID-001",
            "status": "authorized", "bound_pk_i": None,
        }],
    }
    pc.write_message(public_path, public)
    pc.write_message(secret_path, secret)
    pc.write_message(rl_path, {"rl_record": rl_record})
    pc.write_message(legal_path, {
        "device_bindings": [], "root_to_legal_id": [],
    })
    pc.write_message(operational_path, {"root_records": []})
    print(f"Initialized protocol v{pc.PROTOCOL_VERSION}: n={args.n}, m={args.m}")
    print(f"Public parameters: {public_path}")
    print(f"Signed revocation list: {rl_path}")
    print(f"TA secret/device registry (do not copy): {secret_path}")
    print("Next: run ta_phase2_enroll_process.py --issue-challenges.")


if __name__ == "__main__":
    main()
