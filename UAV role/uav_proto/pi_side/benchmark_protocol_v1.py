"""Table-17 benchmark for the revised single-PUF canonical protocol."""

import argparse
import csv
import importlib.util
import json
import os
import platform
import random
import secrets
import statistics
import sys
import time

UAV_SHARED = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "shared")
)
sys.path.insert(0, UAV_SHARED)
crypto_dir = os.path.abspath(
    os.environ.get("FINAL_PROTOCOL_CRYPTO_DIR", UAV_SHARED)
)
if crypto_dir != UAV_SHARED:
    spec = importlib.util.spec_from_file_location(
        "crypto_primitives", os.path.join(crypto_dir, "crypto_primitives.py")
    )
    if spec is None or spec.loader is None:
        raise ImportError("cannot load requested native crypto backend")
    module = importlib.util.module_from_spec(spec)
    sys.modules["crypto_primitives"] = module
    spec.loader.exec_module(module)

import oqs

import admission_control
import crypto_primitives as cp
import fuzzy_extractor
import merkle
import protocol_common as pc
import protocol_messages as pm
import revocation
import seeded_ml_dsa

HERE = os.path.dirname(__file__)
UAV_CTX = b"uav-001"
DEFAULT_N = [1024, 16384]


def _validate_reads(reads):
    if len(reads) != 1023 or any(
        len(row) != 9 or any(bit not in (0, 1) for bit in row)
        for row in reads
    ):
        raise ValueError("PUF vectors must contain 1023 rows of nine bits")


def load_vectors(path):
    if path:
        with open(path, encoding="utf-8") as handle:
            source = json.load(handle)
        enrollment = source.get("enrollment_reads", source.get("enrollment_reads_s1"))
        reconstruction = source.get(
            "reconstruction_reads", source.get("reconstruction_reads_s1")
        )
        label = os.path.abspath(path)
    else:
        rng = random.Random(0x505546)
        bits = [rng.randrange(2) for _ in range(1023)]
        enrollment = [[bit] * 9 for bit in bits]
        reconstruction = [row[:] for row in enrollment]
        for index in range(73, 81):
            reconstruction[index] = [1 - bits[index]] * 9
        label = "deterministic software fixture"
    _validate_reads(enrollment)
    _validate_reads(reconstruction)
    # Timing-vector files contain digital reads but no analog enrollment
    # margins. This deterministic ordering exercises top-950 selection without
    # claiming that the margins came from LTspice or fabricated silicon.
    margins = [0.006 + index / 1_000_000 for index in range(1023)]
    return enrollment, reconstruction, margins, label


def timed(operation, trials):
    operation()  # discarded warm-up
    values = []
    for trial in range(1, trials + 1):
        start = time.perf_counter()
        operation()
        values.append((trial, (time.perf_counter() - start) * 1000))
    return values


def root_state(n, s2, root_nonce, ctx_wire):
    ctx = pm.decode_flight_ctx(ctx_wire)
    seed = pc.kdf_labeled(
        pc.TAG_MERKLE_ROOT, s2, root_nonce, pc.u32(ctx["k"])
    )
    pids, leaves = [], []
    for j in range(1, n + 1):
        x = pc.kdf_labeled(pc.TAG_INTERVAL_SECRET, seed, pc.u32(j))
        pid = pc.hash_labeled(
            pc.TAG_RID, x, pc.u32(j), root_nonce, ctx_wire
        )[:16]
        pids.append(pid)
        leaves.append(merkle.leaf_hash(pid, j, root_nonce, ctx_wire))
    levels = merkle.build_tree(leaves)
    return {
        "pids": pids, "levels": levels, "mr": merkle.root(levels),
        "index": {pid: j + 1 for j, pid in enumerate(pids)},
    }


def fixture(n, enrollment, reconstruction, margins):
    k_puf, helper = fuzzy_extractor.fe_gen(enrollment, margins)
    s1, s2 = pc.derive_purpose_secrets(k_puf, UAV_CTX)
    pk_i, _ = seeded_ml_dsa.seeded_keygen(pc.ML_DSA_ALG, s1)
    kc_i = cp.hash_bytes(pk_i)
    with oqs.Signature(pc.ML_DSA_ALG) as signer:
        pk_ta = signer.generate_keypair()
        sk_ta = signer.export_secret_key()
    with oqs.Signature(pc.ML_DSA_ALG) as signer:
        pk_v = signer.generate_keypair()
        sk_v = signer.export_secret_key()
    now = int(time.time())
    ctx = {
        "k": 0, "delta_t": 60, "n": n, "start_time": now - 1,
        "end_time": now + n * 60, "region": "TEST-REGION",
        "scope": "test-deployment",
    }
    ctx_wire = pm.encode_flight_ctx(ctx)
    root_nonce = secrets.token_bytes(16)
    state = root_state(n, s2, root_nonce, ctx_wire)
    auth_body = pm.encode_root_auth_body(
        pk_i, state["mr"], root_nonce, ctx_wire
    )
    cert_body = pm.encode_cert_body(
        "VERIFIER-001", "Test Ground Control Station", "GCS",
        "test-deployment", now - 60, now + 86400, pk_v,
    )
    rl_body = pm.encode_revocation_body(
        1, now - 60, now + 86400, [], [], []
    )
    with oqs.Signature(pc.ML_DSA_ALG, sk_ta) as signer:
        auth_record = pm.encode_signed_record(
            auth_body, signer.sign(auth_body), pm.TYPE_AUTH_RECORD
        )
        cert_record = pm.encode_signed_record(
            cert_body, signer.sign(cert_body), pm.TYPE_CERT_RECORD
        )
        rl_record = pm.encode_signed_record(
            rl_body, signer.sign(rl_body), pm.TYPE_REVOCATION_RECORD
        )
    rl = revocation.verify_record(rl_record, pk_ta, now=now)
    with oqs.KeyEncapsulation(pc.ML_KEM_ALG) as kem:
        ek_v = kem.generate_keypair()
    n_v = secrets.token_bytes(16)
    auth_ref = state["pids"][1]
    ts_v = now + 60
    request = pm.encode_verifier_request(
        cert_record, ek_v, auth_ref, n_v, ts_v, "test-deployment", 1
    )
    with oqs.Signature(pc.ML_DSA_ALG, sk_v) as signer:
        request_wire = pm.encode_signed_request(request, signer.sign(request))
    return {
        "n": n, "reconstruction": reconstruction, "helper": helper,
        "s2": s2, "pk_i": pk_i, "kc_i": kc_i, "pk_ta": pk_ta,
        "pk_v": pk_v, "root_nonce": root_nonce, "ctx_wire": ctx_wire,
        "state": state, "auth_record": auth_record, "root_id": cp.hash_bytes(auth_record),
        "cert_record": cert_record, "rl_record": rl_record, "rl": rl,
        "request_wire": request_wire,
    }


def activate(f):
    revocation.verify_record(f["rl_record"], f["pk_ta"])
    body, signature = pm.decode_signed_record(
        f["auth_record"], pm.TYPE_AUTH_RECORD
    )
    with oqs.Signature(pc.ML_DSA_ALG) as verifier:
        if not verifier.verify(body, signature, f["pk_ta"]):
            raise RuntimeError("root signature fixture failed")
    k_puf = fuzzy_extractor.fe_rec(f["reconstruction"], f["helper"])
    if k_puf is None:
        raise RuntimeError("PUF reconstruction failed")
    _, s2 = pc.derive_purpose_secrets(k_puf, UAV_CTX)
    state = root_state(f["n"], s2, f["root_nonce"], f["ctx_wire"])
    if state["mr"] != f["state"]["mr"]:
        raise RuntimeError("activation root mismatch")
    return state


def uav_authenticate(f):
    request_wire, sigma_v = pm.decode_signed_request(f["request_wire"])
    request = pm.decode_verifier_request(request_wire)
    controller = admission_control.AdmissionController(
        global_rate=1000, global_burst=2, per_cert_rate=1000,
        per_cert_burst=2, pair_gap_seconds=0,
    )
    controller.pre_auth()
    cert_body, cert_sig = pm.decode_signed_record(
        request["cert_record"], pm.TYPE_CERT_RECORD
    )
    cert = pm.decode_cert_body(cert_body)
    with oqs.Signature(pc.ML_DSA_ALG) as verifier:
        if not verifier.verify(cert_body, cert_sig, f["pk_ta"]):
            raise RuntimeError("certificate fixture failed")
        if not verifier.verify(request_wire, sigma_v, cert["pk_v"]):
            raise RuntimeError("request fixture failed")
    rl = f["rl"]
    if request["revocation_version"] != rl["version"]:
        raise RuntimeError("revocation version fixture failed")
    if cert["scope"] != "test-deployment" or request["requested_scope"] != cert["scope"]:
        raise RuntimeError("scope fixture failed")
    if not cert["valid_from"] <= request["ts_v"] <= cert["valid_until"]:
        raise RuntimeError("certificate validity fixture failed")
    cert_id = cp.hash_bytes(request["cert_record"])
    revocation.assert_not_revoked(
        rl, cert_id=cert_id, root_id=f["root_id"],
        key_id_value=cp.hash_bytes(f["pk_i"]),
    )
    req_id = pc.compute_req_id(request_wire)
    controller.admit(
        cert_id, request["auth_ref"], request["n_v"], req_id,
    )
    try:
        ctx = pm.decode_flight_ctx(f["ctx_wire"])
        j = 1 + (request["ts_v"] - ctx["start_time"]) // ctx["delta_t"]
        if request["auth_ref"] != f["state"]["pids"][j - 1]:
            raise RuntimeError("time-derived interval fixture failed")
        path = merkle.auth_path(f["state"]["levels"], j)
        with oqs.KeyEncapsulation(pc.ML_KEM_ALG) as kem:
            ct, ss = kem.encap_secret(request["ek_v"])
        request_hash = cp.hash_bytes(request_wire)
        k_sess = pc.kdf_labeled(
            pc.TAG_RID_AUTH, ss, req_id, request_hash
        )[:16]
        k_puf = fuzzy_extractor.fe_rec(f["reconstruction"], f["helper"])
        if k_puf is None:
            raise RuntimeError("PUF reconstruction failed")
        s1, _ = pc.derive_purpose_secrets(k_puf, UAV_CTX)
        pk_i, sk_i = seeded_ml_dsa.seeded_keygen(pc.ML_DSA_ALG, s1)
        if pk_i != f["pk_i"] or cp.hash_bytes(pk_i) != f["kc_i"]:
            raise RuntimeError("key confirmation failed")
        ts_d = request["ts_v"]
        transcript = pm.encode_auth_transcript(
            req_id, request["auth_ref"], request["auth_ref"], j,
            f["root_id"], request["n_v"], request["ts_v"], ts_d, ct,
        )
        with oqs.Signature(pc.ML_DSA_ALG, sk_i) as signer:
            sigma_d = signer.sign(transcript)
        payload = pm.encode_payload(
            request["auth_ref"], request["auth_ref"], j, path,
            f["root_id"], ts_d, sigma_d,
        )
        nonce = pc.compute_aead_nonce(req_id, ct)
        ad = pm.encode_aead_ad(req_id, ct, nonce, request_hash)
        ciphertext = cp.aead_encrypt(k_sess, nonce, ad, payload)
        return pm.encode_response_outer(req_id, ct, nonce, ciphertext)
    finally:
        controller.release()


def write_results(raw, summary, sizes, metadata, suffix, force):
    raw_path = os.path.join(HERE, f"results_protocol_v1_trials{suffix}.csv")
    summary_path = os.path.join(HERE, f"results_protocol_v1_summary{suffix}.csv")
    json_path = os.path.join(HERE, f"results_protocol_v1{suffix}.json")
    tex_path = os.path.join(HERE, f"results_protocol_v1_rows{suffix}.tex")
    existing = [
        path for path in (raw_path, summary_path, json_path, tex_path)
        if os.path.exists(path)
    ]
    if existing and not force:
        raise SystemExit(
            "Refusing to overwrite existing benchmark output; preserve it or "
            "rerun with --force."
        )
    with open(raw_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["operation", "n", "trial", "latency_ms"]
        )
        writer.writeheader()
        writer.writerows(raw)
    with open(summary_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["operation", "n", "mean_ms", "std_ms", "trials"]
        )
        writer.writeheader()
        writer.writerows(summary)
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "metadata": metadata, "raw_trials": raw,
                "summary": summary, "sizes": sizes,
            },
            handle, indent=2,
        )
    with open(tex_path, "w", encoding="utf-8") as handle:
        for row in summary:
            handle.write(
                f"{row['operation']} & {row['n']} & "
                f"{row['mean_ms']:.3f} & {row['std_ms']:.3f} \\\\\n"
            )
    for path in (raw_path, summary_path, json_path, tex_path):
        print(f"Wrote {path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", nargs="+", type=int, default=DEFAULT_N)
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--puf-vectors")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if args.trials < 1 or any(n < 1 or n & (n - 1) for n in args.n):
        parser.error("trials must be positive and every n must be a power of two")
    enrollment, reconstruction, margins, source = load_vectors(args.puf_vectors)
    raw, summary, sizes = [], [], []
    fixtures = [
        fixture(n, enrollment, reconstruction, margins) for n in args.n
    ]
    puf_samples = timed(
        lambda: fuzzy_extractor.fe_rec(
            reconstruction, fixtures[0]["helper"]
        ),
        args.trials,
    )
    puf_values = [value for _, value in puf_samples]
    puf_name = "PUF reconstruction + BCH(950,870) + Toeplitz-256"
    raw.extend({
        "operation": puf_name, "n": "", "trial": trial,
        "latency_ms": value,
    } for trial, value in puf_samples)
    summary.append({
        "operation": puf_name, "n": "-",
        "mean_ms": statistics.mean(puf_values),
        "std_ms": (
            statistics.stdev(puf_values) if len(puf_values) > 1 else 0.0
        ),
        "trials": args.trials,
    })
    for f in fixtures:
        n = f["n"]
        operations = [
            ("One Merkle-root generation", lambda: root_state(
                n, f["s2"], f["root_nonce"], f["ctx_wire"]
            )),
            ("Pre-flight root activation (Algorithm 3)", lambda: activate(f)),
            ("On-demand authentication (Algorithms 5+6, UAV)", lambda: uav_authenticate(f)),
        ]
        response = uav_authenticate(f)
        sizes.append({
            "n": n, "request_bytes": len(f["request_wire"]),
            "response_bytes": len(response),
            "broadcast_uas_id_bytes": 20,
            "merkle_path_entries": n.bit_length() - 1,
            "merkle_path_encoded_bytes": (
                2 + (n.bit_length() - 1) * 49
            ),
            "auth_record_bytes": len(f["auth_record"]),
            "cert_record_bytes": len(f["cert_record"]),
            "revocation_record_bytes": len(f["rl_record"]),
            "helper_data_local_json_bytes": len(
                pc.serialize_message_bytes(f["helper"])
            ),
            "interval_journal_bytes": 0,
        })
        for name, operation in operations:
            samples = timed(operation, args.trials)
            values = [value for _, value in samples]
            raw.extend({
                "operation": name, "n": n, "trial": trial,
                "latency_ms": value,
            } for trial, value in samples)
            summary.append({
                "operation": name, "n": n,
                "mean_ms": statistics.mean(values),
                "std_ms": statistics.stdev(values) if len(values) > 1 else 0.0,
                "trials": args.trials,
            })
    suffix = "" if args.n == DEFAULT_N and args.trials == 30 and args.puf_vectors else "_quicktest"
    metadata = {
        "protocol_version": pc.PROTOCOL_VERSION,
        "platform": platform.platform(), "machine": platform.machine(),
        "python": platform.python_version(), "puf_vector_source": source,
        "puf_margin_source": "deterministic timing fixture; not LTspice or silicon",
        "warmup_discarded": 1, "trials": args.trials,
        "physical_puf_acquisition_latency": "excluded/unavailable",
        "transport_latency": "excluded",
        "admission_fixture": (
            "fresh isolated replay/rate-limit state constructed per timed "
            "authentication so an identical signed request can be repeated"
        ),
    }
    write_results(raw, summary, sizes, metadata, suffix, args.force)


if __name__ == "__main__":
    main()
