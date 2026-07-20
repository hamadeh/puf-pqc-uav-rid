"""
benchmark_final_protocol.py

Remeasures the final Profile-P protocol implementation at its actual wire
boundaries.  It replaces assumptions made by the older Table 17 harness:

* full root activation includes supplied-vector PUF reconstruction, Merkle
  root recomputation/validation, and sorted PIDIndex construction;
* AuthRef lookup uses the final sorted index;
* request/response sizes use the exact JSON emitted by write_message();
* complete UAV and verifier software timings include serialization;
* physical PUF acquisition, transport, and energy are reported as
  unavailable rather than estimated.

The benchmark never times generation of PUF readings.  Each reconstruction
receives a complete 1023-challenge x 9-read vector prepared before the
timer starts.  Pass --puf-vectors to use captured/supplied vectors; the
default deterministic fixture exists only for software-path smoke tests.

Captured-vector JSON format:

    {
      "enrollment_reads_s1": [[0, ... nine bits ...], ... 1023 rows ...],
      "reconstruction_reads_s1": [[0, ... nine bits ...], ... 1023 rows ...],
      "enrollment_reads_s2": [[0, ... nine bits ...], ... 1023 rows ...],
      "reconstruction_reads_s2": [[0, ... nine bits ...], ... 1023 rows ...]
    }

For compatibility, the older two-key form (enrollment_reads and
reconstruction_reads) is accepted and used for both channels.  The final
implementation has two independent PUF/FE channels, so four-channel input
is preferred for reported results.

Run on the measurement target after building liboqs, bchlib, and the native
Ascon libraries:

    python3 benchmark_final_protocol.py
    python3 benchmark_final_protocol.py --n 16 --trials 3
    python3 benchmark_final_protocol.py --puf-vectors captured_vectors.json

If the verifier and UAV run on different hardware, run this harness on each
machine and use the role-specific rows from the corresponding run.  A single
run records the host platform for every row; it does not invent cross-machine
transport latency.
"""

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

HERE = os.path.dirname(os.path.abspath(__file__))
UAV_SHARED = os.path.abspath(os.path.join(HERE, "..", "shared"))
CRYPTO_SHARED = os.environ.get("FINAL_PROTOCOL_CRYPTO_DIR", UAV_SHARED)

# FINAL_PROTOCOL_CRYPTO_DIR is useful when running the same benchmark on
# the verifier computer, whose native Ascon libraries live in its own
# shared directory.  Load only crypto_primitives from that directory; the
# remaining protocol modules must continue to come from the UAV shared
# implementation because the verifier tree does not contain the PUF modules.
sys.path.insert(0, UAV_SHARED)
if os.path.abspath(CRYPTO_SHARED) != UAV_SHARED:
    crypto_path = os.path.join(
        os.path.abspath(CRYPTO_SHARED), "crypto_primitives.py"
    )
    crypto_spec = importlib.util.spec_from_file_location(
        "crypto_primitives", crypto_path
    )
    if crypto_spec is None or crypto_spec.loader is None:
        raise ImportError(f"cannot load crypto backend from {crypto_path}")
    crypto_module = importlib.util.module_from_spec(crypto_spec)
    sys.modules["crypto_primitives"] = crypto_module
    crypto_spec.loader.exec_module(crypto_module)

import crypto_primitives as cp
import majority_vote
import merkle
import pid_index
import protocol_common as pc
import puf_pipeline_1023 as pp
import seeded_ml_dsa
import tuple_hash256

import oqs

ML_DSA_ALG = "ML-DSA-65"
ML_KEM_ALG = "ML-KEM-768"
UAV_CTX = b"uav-001"
SCOPE = "test-deployment"
DEFAULT_N_VALUES = [1024, 16384]
DEFAULT_TRIALS = 30
FIXED_TS_V = 1_700_000_000.0
FIXED_TS_D = 1_700_000_001.0


def validate_reads(name: str, reads: list) -> None:
    expected_rows = majority_vote.NUM_CHALLENGES
    expected_width = majority_vote.READS_PER_CHALLENGE
    if len(reads) != expected_rows:
        raise ValueError(f"{name} must contain {expected_rows} challenge rows")
    for row_number, row in enumerate(reads):
        if len(row) != expected_width or any(bit not in (0, 1) for bit in row):
            raise ValueError(
                f"{name}[{row_number}] must contain exactly "
                f"{expected_width} binary values"
            )


def load_puf_vectors(path: str | None) -> tuple[dict, str]:
    if path:
        with open(path, "r", encoding="utf-8") as handle:
            vectors = json.load(handle)
        source = os.path.abspath(path)
    else:
        # Deterministic, same-shaped two-channel fixture.  Four majority
        # outputs differ in each channel, forcing BCH correction without
        # making a physical-PUF or entropy claim.
        vectors = {}
        for channel, seed, challenges in (
            ("s1", 0x505546, (7, 101, 503, 901)),
            ("s2", 0x534543, (11, 211, 607, 997)),
        ):
            rng = random.Random(seed)
            true_bits = [
                rng.randrange(2) for _ in range(majority_vote.NUM_CHALLENGES)
            ]
            enrollment = [
                [bit] * majority_vote.READS_PER_CHALLENGE
                for bit in true_bits
            ]
            reconstruction = [row.copy() for row in enrollment]
            for challenge in challenges:
                for read_index in range(5):
                    reconstruction[challenge][read_index] ^= 1
            vectors[f"enrollment_reads_{channel}"] = enrollment
            vectors[f"reconstruction_reads_{channel}"] = reconstruction
        source = "deterministic two-channel software fixture (NOT physical PUF data)"

    # Accept the original two-key fixture format, but normalize internally
    # to the final implementation's independent S1/S2 channels.
    if "enrollment_reads" in vectors or "reconstruction_reads" in vectors:
        if not {
            "enrollment_reads", "reconstruction_reads"
        }.issubset(vectors):
            raise ValueError(
                "legacy PUF vector files must contain both enrollment_reads "
                "and reconstruction_reads"
            )
        vectors = {
            "enrollment_reads_s1": vectors["enrollment_reads"],
            "reconstruction_reads_s1": vectors["reconstruction_reads"],
            "enrollment_reads_s2": vectors["enrollment_reads"],
            "reconstruction_reads_s2": vectors["reconstruction_reads"],
        }
        source += " (legacy two-key input reused for S1 and S2)"

    required = (
        "enrollment_reads_s1", "reconstruction_reads_s1",
        "enrollment_reads_s2", "reconstruction_reads_s2",
    )
    for key in required:
        if key not in vectors:
            raise ValueError(f"PUF vector file is missing {key!r}")
        validate_reads(key, vectors[key])
    return vectors, source


def time_samples(fn, trials: int) -> list[float]:
    fn()  # warmup, discarded
    samples = []
    for _ in range(trials):
        start = time.perf_counter_ns()
        fn()
        end = time.perf_counter_ns()
        samples.append((end - start) / 1_000_000)
    return samples


def timing_row(operation: str, side: str, n, samples: list[float],
               notes: str = "") -> dict:
    return {
        "operation": operation,
        "side": side,
        "n": n,
        "mean_ms": round(statistics.mean(samples), 6),
        "std_ms": round(statistics.pstdev(samples), 6),
        "min_ms": round(min(samples), 6),
        "max_ms": round(max(samples), 6),
        "trials": len(samples),
        "notes": notes,
    }


def cert_payload(cert_vj: dict) -> bytes:
    validity = json.dumps(cert_vj["validity_j"], sort_keys=True).encode("utf-8")
    return (
        cert_vj["vid_j"].encode("utf-8")
        + cert_vj["pk_vj"]
        + cert_vj["scope_j"].encode("utf-8")
        + validity
    )


def auth_record_payload(record: dict) -> bytes:
    flight_ctx = json.dumps(record["flight_ctx"], sort_keys=True).encode("utf-8")
    return (
        record["pk_i"]
        + record["mr_k"]
        + record["root_nonce"]
        + flight_ctx
    )


def build_root_state(n: int, s2: bytes, root_nonce: bytes, k: int,
                     flight_ctx: dict) -> dict:
    flight_ctx_bytes = pc.canonical_json_bytes(flight_ctx)
    seed_k = cp.kdf(
        s2, root_nonce, k.to_bytes(4, "big"), pc.TAG_MERKLE_ROOT
    )
    pids = []
    leaves = []
    for j in range(n):
        j_bytes = j.to_bytes(4, "big")
        x_kj = cp.kdf(seed_k, j_bytes, pc.TAG_INTERVAL_SECRET)
        pid_kj = cp.hash_bytes(
            pc.TAG_RID + x_kj + j_bytes + root_nonce + flight_ctx_bytes
        )[:16]
        pids.append(pid_kj)
        leaves.append(merkle.leaf_hash(pid_kj, j, root_nonce, flight_ctx_bytes))
    levels = merkle.build_tree(leaves)
    return {
        "pids": pids,
        "levels": levels,
        "pid_index": pid_index.build_pid_index(pids),
        "mr_k": merkle.root(levels),
        "flight_ctx_bytes": flight_ctx_bytes,
    }


def build_identity(vectors: dict) -> dict:
    k_puf_s1, bch_ecc_s1, toeplitz_seed_s1 = pp.fe_gen_1023(
        vectors["enrollment_reads_s1"]
    )
    k_puf_s2, bch_ecc_s2, toeplitz_seed_s2 = pp.fe_gen_1023(
        vectors["enrollment_reads_s2"]
    )
    s1 = cp.kdf(k_puf_s1, pc.TAG_ML_DSA, UAV_CTX)
    s2 = cp.kdf(k_puf_s2, pc.TAG_MERKLE_ROOT, UAV_CTX)
    pk_i, sk_i = seeded_ml_dsa.seeded_keygen(ML_DSA_ALG, s1)

    with oqs.Signature(ML_DSA_ALG) as signer:
        pk_ta = signer.generate_keypair()
        sk_ta = signer.export_secret_key()
    with oqs.Signature(ML_DSA_ALG) as signer:
        pk_vj = signer.generate_keypair()
        sk_vj = signer.export_secret_key()

    validity = {
        "start": "2026-01-01T00:00:00Z",
        "end": "2026-12-31T23:59:59Z",
    }
    cert_vj = {
        "vid_j": "verifier-001",
        "pk_vj": pk_vj,
        "scope_j": SCOPE,
        "validity_j": validity,
    }
    with oqs.Signature(ML_DSA_ALG, sk_ta) as signer:
        cert_vj["signature"] = signer.sign(cert_payload(cert_vj))

    return {
        "bch_ecc_s1": bch_ecc_s1,
        "toeplitz_seed_s1": toeplitz_seed_s1,
        "bch_ecc_s2": bch_ecc_s2,
        "toeplitz_seed_s2": toeplitz_seed_s2,
        "s1": s1,
        "s2": s2,
        "pk_i": pk_i,
        "sk_i": sk_i,
        "kc_i": cp.hash_bytes(pk_i),
        "pk_ta": pk_ta,
        "sk_ta": sk_ta,
        "cert_vj": cert_vj,
        "pk_vj": pk_vj,
        "sk_vj": sk_vj,
    }


def make_context(n: int, identity: dict) -> dict:
    flight_ctx = {
        "k": 0,
        "delta_t": 1,
        "n": n,
        "scope": SCOPE,
        "validity": {
            "start": "2026-01-01T00:00:00Z",
            "end": "2026-12-31T23:59:59Z",
            "max_intervals": n,
            "region": "test-region",
        },
    }
    root_nonce = secrets.token_bytes(16)
    root_state = build_root_state(n, identity["s2"], root_nonce, 0, flight_ctx)
    root_record = {
        "pk_i": identity["pk_i"],
        "mr_k": root_state["mr_k"],
        "root_nonce": root_nonce,
        "flight_ctx": flight_ctx,
    }
    with oqs.Signature(ML_DSA_ALG, identity["sk_ta"]) as signer:
        root_record["auth_rec_signature"] = signer.sign(
            auth_record_payload(root_record)
        )
    return {
        "n": n,
        "flight_ctx": flight_ctx,
        "root_nonce": root_nonce,
        "root_state": root_state,
        "root_record": root_record,
        "auth_db": {"root_records": [root_record]},
        "auth_ref": root_state["pids"][n // 2],
    }


def full_activation(context: dict, identity: dict, vectors: dict) -> dict:
    # The 1023x9 reconstruction vector is already supplied.  No acquisition,
    # file parsing, random-vector generation, or hardware wait is timed here.
    k_puf = pp.fe_rec_1023(
        vectors["reconstruction_reads_s2"],
        identity["bch_ecc_s2"],
        identity["toeplitz_seed_s2"],
    )
    if k_puf is None:
        raise RuntimeError("BCH reconstruction failed for supplied vectors")
    s2 = cp.kdf(k_puf, pc.TAG_MERKLE_ROOT, UAV_CTX)
    state = build_root_state(
        context["n"], s2, context["root_nonce"], 0, context["flight_ctx"]
    )
    if state["mr_k"] != context["root_record"]["mr_k"]:
        raise RuntimeError("activated Merkle root does not match enrollment")
    return state


def generate_verifier_request(identity: dict, auth_ref: bytes) -> tuple[bytes, dict]:
    with oqs.KeyEncapsulation(ML_KEM_ALG) as kem:
        ek_vj = kem.generate_keypair()
        dk_vj = kem.export_secret_key()
    n_v = secrets.token_bytes(16)
    req_auth = {
        "cert_vj": identity["cert_vj"],
        "ek_vj": ek_vj,
        "auth_ref": auth_ref,
        "n_v": n_v,
        "ts_v": FIXED_TS_V,
        "scope_j": SCOPE,
    }
    req_auth_bytes = pc.canonical_json_bytes(req_auth)
    h_req_auth = cp.hash_bytes(req_auth_bytes)
    with oqs.Signature(ML_DSA_ALG, identity["sk_vj"]) as signer:
        sigma_vj = signer.sign(h_req_auth)
    wire = pc.serialize_message_bytes({
        "req_auth": req_auth,
        "sigma_vj": sigma_vj,
    })
    pending = {
        "dk_vj": dk_vj,
        "n_v": n_v,
        "ts_v": FIXED_TS_V,
        "req_auth_bytes": req_auth_bytes,
        "auth_ref": auth_ref,
    }
    return wire, pending


def process_uav_request(request_wire: bytes, context: dict, identity: dict,
                        vectors: dict, return_details: bool = False):
    incoming = pc.deserialize_message_bytes(request_wire)
    req_auth = incoming["req_auth"]
    sigma_vj = incoming["sigma_vj"]
    cert_vj = req_auth["cert_vj"]

    with oqs.Signature(ML_DSA_ALG) as verifier:
        if not verifier.verify(
            cert_payload(cert_vj), cert_vj["signature"], identity["pk_ta"]
        ):
            raise RuntimeError("verifier certificate rejected")

    req_auth_bytes = pc.canonical_json_bytes(req_auth)
    h_req_auth = cp.hash_bytes(req_auth_bytes)
    req_id = pc.compute_req_id(req_auth_bytes)
    with oqs.Signature(ML_DSA_ALG) as verifier:
        if not verifier.verify(h_req_auth, sigma_vj, cert_vj["pk_vj"]):
            raise RuntimeError("verifier request signature rejected")

    if req_auth["scope_j"] != SCOPE or cert_vj["scope_j"] != SCOPE:
        raise RuntimeError("request scope rejected")

    state = context["root_state"]
    j = pid_index.indexed_find_j(state["pid_index"], req_auth["auth_ref"])
    if j < 0:
        raise RuntimeError("AuthRef is absent from PIDIndex")
    pid_kj = state["pids"][j]
    auth_path = merkle.auth_path(state["levels"], j)

    with oqs.KeyEncapsulation(ML_KEM_ALG) as kem:
        ct, ss = kem.encap_secret(req_auth["ek_vj"])
    k_sess = cp.kdf(
        ss,
        req_auth["n_v"],
        req_auth["auth_ref"],
        str(req_auth["ts_v"]).encode("utf-8"),
        h_req_auth,
        pc.TAG_RID_AUTH,
    )[:16]
    nonce = pc.compute_aead_nonce(req_id, ct)

    k_puf = pp.fe_rec_1023(
        vectors["reconstruction_reads_s1"],
        identity["bch_ecc_s1"],
        identity["toeplitz_seed_s1"],
    )
    if k_puf is None:
        raise RuntimeError("BCH reconstruction failed")
    seed_sig = cp.kdf(k_puf, pc.TAG_ML_DSA, UAV_CTX)
    pk_i, sk_i = seeded_ml_dsa.seeded_keygen(ML_DSA_ALG, seed_sig)
    if cp.hash_bytes(pk_i) != identity["kc_i"]:
        raise RuntimeError("deterministic UAV key confirmation failed")

    transcript = tuple_hash256.tuple_hash256(
        pc.TAG_AUTH_TRANSCRIPT,
        req_auth["auth_ref"],
        pid_kj,
        j,
        context["root_record"]["mr_k"],
        context["root_nonce"],
        state["flight_ctx_bytes"],
        req_auth["n_v"],
        str(FIXED_TS_D).encode("utf-8"),
        ct,
        h_req_auth,
    )
    with oqs.Signature(ML_DSA_ALG, sk_i) as signer:
        sigma_d = signer.sign(transcript)

    payload = {
        "auth_ref": req_auth["auth_ref"],
        "pid": pid_kj,
        "j": j,
        "root_nonce": context["root_nonce"],
        "flight_ctx": context["flight_ctx"],
        "auth_path": auth_path,
        "mr_k": context["root_record"]["mr_k"],
        "auth_rec_signature": context["root_record"]["auth_rec_signature"],
        "ts_d": FIXED_TS_D,
        "sigma_d": sigma_d,
    }
    plaintext = pc.canonical_json_bytes(payload)
    ad = pc.canonical_json_bytes({
        "req_id": req_id,
        "ct": ct,
        "n_a": nonce,
        "h_req_auth": h_req_auth,
    })
    ciphertext = cp.aead_encrypt(k_sess, nonce, ad, plaintext)
    response_wire = pc.serialize_message_bytes({
        "req_id": req_id,
        "ct": ct,
        "nonce": nonce,
        "ciphertext": ciphertext,
    })

    if not return_details:
        return response_wire
    return response_wire, {
        "request": req_auth,
        "request_hash": h_req_auth,
        "request_signature": sigma_vj,
        "request_bytes": req_auth_bytes,
        "req_id": req_id,
        "j": j,
        "auth_path": auth_path,
        "ct": ct,
        "shared_secret": ss,
        "session_key": k_sess,
        "nonce": nonce,
        "transcript": transcript,
        "uav_secret_key": sk_i,
        "uav_signature": sigma_d,
        "plaintext": plaintext,
        "associated_data": ad,
        "ciphertext": ciphertext,
    }


def process_verifier_response(response_wire: bytes, pending: dict,
                              context: dict, identity: dict) -> bool:
    response = pc.deserialize_message_bytes(response_wire)
    h_req_auth = cp.hash_bytes(pending["req_auth_bytes"])
    req_id = pc.compute_req_id(pending["req_auth_bytes"])
    if response["req_id"] != req_id:
        raise RuntimeError("ReqID mismatch")

    with oqs.KeyEncapsulation(ML_KEM_ALG, pending["dk_vj"]) as kem:
        ss = kem.decap_secret(response["ct"])
    k_sess = cp.kdf(
        ss,
        pending["n_v"],
        pending["auth_ref"],
        str(pending["ts_v"]).encode("utf-8"),
        h_req_auth,
        pc.TAG_RID_AUTH,
    )[:16]
    nonce = pc.compute_aead_nonce(req_id, response["ct"])
    if response["nonce"] != nonce:
        raise RuntimeError("AEAD nonce mismatch")
    ad = pc.canonical_json_bytes({
        "req_id": req_id,
        "ct": response["ct"],
        "n_a": nonce,
        "h_req_auth": h_req_auth,
    })
    plaintext = cp.aead_decrypt(
        k_sess, nonce, ad, response["ciphertext"]
    )
    if plaintext is None:
        raise RuntimeError("Ascon-AEAD authentication failed")
    payload = pc.decode_canonical_json(plaintext)

    matching = None
    for record in context["auth_db"]["root_records"]:
        if record["root_nonce"] == payload["root_nonce"]:
            matching = record
            break
    if matching is None:
        raise RuntimeError("root absent from verifier AuthDB")

    with oqs.Signature(ML_DSA_ALG) as verifier:
        if not verifier.verify(
            auth_record_payload(matching),
            payload["auth_rec_signature"],
            identity["pk_ta"],
        ):
            raise RuntimeError("TA root authorization rejected")

    flight_ctx_bytes = pc.canonical_json_bytes(matching["flight_ctx"])
    leaf = merkle.leaf_hash(
        payload["pid"], payload["j"], payload["root_nonce"], flight_ctx_bytes
    )
    if not merkle.verify_path(
        leaf, payload["j"], payload["auth_path"], matching["mr_k"]
    ):
        raise RuntimeError("Merkle path rejected")

    transcript = tuple_hash256.tuple_hash256(
        pc.TAG_AUTH_TRANSCRIPT,
        pending["auth_ref"],
        payload["pid"],
        payload["j"],
        matching["mr_k"],
        payload["root_nonce"],
        flight_ctx_bytes,
        pending["n_v"],
        str(payload["ts_d"]).encode("utf-8"),
        response["ct"],
        h_req_auth,
    )
    with oqs.Signature(ML_DSA_ALG) as verifier:
        if not verifier.verify(
            transcript, payload["sigma_d"], matching["pk_i"]
        ):
            raise RuntimeError("UAV transcript signature rejected")
    return True


def primitive_rows(trials: int, identity: dict, vectors: dict,
                   context: dict, details: dict, pending: dict) -> list[dict]:
    rows = []
    n = context["n"]

    rows.append(timing_row(
        "PUF-vector processing + BCH reconstruction + Toeplitz (S1)",
        "UAV", "-", time_samples(
            lambda: pp.fe_rec_1023(
                vectors["reconstruction_reads_s1"],
                identity["bch_ecc_s1"],
                identity["toeplitz_seed_s1"],
            ),
            trials,
        ),
        "1023x9 vector supplied before timer; physical acquisition excluded",
    ))
    rows.append(timing_row(
        "PUF-vector processing + BCH reconstruction + Toeplitz (S2)",
        "UAV", "-", time_samples(
            lambda: pp.fe_rec_1023(
                vectors["reconstruction_reads_s2"],
                identity["bch_ecc_s2"],
                identity["toeplitz_seed_s2"],
            ),
            trials,
        ),
        "1023x9 vector supplied before timer; physical acquisition excluded",
    ))
    rows.append(timing_row(
        "Deterministic ML-DSA-65 key regeneration",
        "UAV", "-", time_samples(
            lambda: seeded_ml_dsa.seeded_keygen(ML_DSA_ALG, identity["s1"]),
            trials,
        ),
    ))

    ek_vj = details["request"]["ek_vj"]
    rows.append(timing_row(
        "ML-KEM-768 encapsulation", "UAV", "-", time_samples(
            lambda: _kem_encapsulate(ek_vj), trials
        ),
    ))
    rows.append(timing_row(
        "ML-KEM-768 decapsulation", "Verifier", "-", time_samples(
            lambda: _kem_decapsulate(pending["dk_vj"], details["ct"]), trials
        ),
    ))

    request_hash = details["request_hash"]
    request_signature = details["request_signature"]
    rows.append(timing_row(
        "Verifier-request ML-DSA signature generation",
        "Verifier", "-", time_samples(
            lambda: _sign(identity["sk_vj"], request_hash), trials
        ),
    ))
    rows.append(timing_row(
        "Verifier-request ML-DSA signature verification",
        "UAV", "-", time_samples(
            lambda: _verify(identity["pk_vj"], request_hash, request_signature),
            trials,
        ),
    ))
    rows.append(timing_row(
        "UAV transcript ML-DSA signature generation",
        "UAV", "-", time_samples(
            lambda: _sign(details["uav_secret_key"], details["transcript"]),
            trials,
        ),
    ))
    rows.append(timing_row(
        "UAV transcript ML-DSA signature verification",
        "Verifier", "-", time_samples(
            lambda: _verify(
                identity["pk_i"], details["transcript"], details["uav_signature"]
            ),
            trials,
        ),
    ))
    rows.append(timing_row(
        "Ascon-AEAD128 encryption", "UAV", n, time_samples(
            lambda: cp.aead_encrypt(
                details["session_key"],
                details["nonce"],
                details["associated_data"],
                details["plaintext"],
            ),
            trials,
        ),
        f"plaintext={len(details['plaintext'])} bytes",
    ))
    rows.append(timing_row(
        "Ascon-AEAD128 decryption", "Verifier", n, time_samples(
            lambda: cp.aead_decrypt(
                details["session_key"],
                details["nonce"],
                details["associated_data"],
                details["ciphertext"],
            ),
            trials,
        ),
        f"ciphertext+tag={len(details['ciphertext'])} bytes",
    ))
    return rows


def _kem_encapsulate(public_key: bytes):
    with oqs.KeyEncapsulation(ML_KEM_ALG) as kem:
        return kem.encap_secret(public_key)


def _kem_decapsulate(secret_key: bytes, ciphertext: bytes):
    with oqs.KeyEncapsulation(ML_KEM_ALG, secret_key) as kem:
        return kem.decap_secret(ciphertext)


def _sign(secret_key: bytes, message: bytes) -> bytes:
    with oqs.Signature(ML_DSA_ALG, secret_key) as signer:
        return signer.sign(message)


def _verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    with oqs.Signature(ML_DSA_ALG) as verifier:
        valid = verifier.verify(message, signature, public_key)
    if not valid:
        raise RuntimeError("signature fixture failed verification")
    return valid


def complete_verifier_samples(trials: int, context: dict, identity: dict,
                              vectors: dict) -> list[float]:
    def one_sample() -> float:
        start = time.perf_counter_ns()
        request_wire, pending = generate_verifier_request(
            identity, context["auth_ref"]
        )
        request_end = time.perf_counter_ns()
        # UAV processing is intentionally outside the verifier timer.
        response_wire = process_uav_request(
            request_wire, context, identity, vectors
        )
        response_start = time.perf_counter_ns()
        process_verifier_response(response_wire, pending, context, identity)
        end = time.perf_counter_ns()
        return ((request_end - start) + (end - response_start)) / 1_000_000

    one_sample()
    return [one_sample() for _ in range(trials)]


def complete_end_to_end_samples(trials: int, context: dict, identity: dict,
                                vectors: dict) -> list[float]:
    """Measure request generation, UAV processing, and verifier processing.

    This is software-only end-to-end latency.  It deliberately excludes
    radio/file-copy transport and physical PUF acquisition, both of which
    are reported separately as unavailable or not measured.
    """
    def one_sample() -> float:
        start = time.perf_counter_ns()
        request_wire, pending = generate_verifier_request(
            identity, context["auth_ref"]
        )
        response_wire = process_uav_request(
            request_wire, context, identity, vectors
        )
        process_verifier_response(response_wire, pending, context, identity)
        end = time.perf_counter_ns()
        return (end - start) / 1_000_000

    one_sample()
    return [one_sample() for _ in range(trials)]


def benchmark_context(n: int, trials: int, identity: dict,
                      vectors: dict) -> tuple[list[dict], list[dict]]:
    context = make_context(n, identity)
    request_wire, pending = generate_verifier_request(
        identity, context["auth_ref"]
    )
    response_wire, details = process_uav_request(
        request_wire, context, identity, vectors, return_details=True
    )
    if not process_verifier_response(
        response_wire, pending, context, identity
    ):
        raise RuntimeError("representative final protocol exchange failed")

    rows = []
    rows.append(timing_row(
        "Full root activation including sorted PIDIndex construction",
        "UAV", n, time_samples(
            lambda: full_activation(context, identity, vectors), trials
        ),
        "includes supplied-vector reconstruction; excludes physical acquisition",
    ))
    rows.append(timing_row(
        "Indexed pseudonym lookup", "UAV", n, time_samples(
            lambda: pid_index.indexed_find_j(
                context["root_state"]["pid_index"], context["auth_ref"]
            ),
            trials,
        ),
        "bisect over sorted (PID,j) entries",
    ))
    lookup_j = pid_index.indexed_find_j(
        context["root_state"]["pid_index"], context["auth_ref"]
    )
    rows.append(timing_row(
        "Merkle-path extraction", "UAV", n, time_samples(
            lambda: merkle.auth_path(
                context["root_state"]["levels"], lookup_j
            ),
            trials,
        ),
        f"path_nodes={len(details['auth_path'])}",
    ))
    rows.extend(primitive_rows(
        trials, identity, vectors, context, details, pending
    ))

    rows.append(timing_row(
        "Complete verifier request generation + serialization",
        "Verifier", n, time_samples(
            lambda: generate_verifier_request(identity, context["auth_ref"]),
            trials,
        ),
        "includes ephemeral ML-KEM key generation and request signature",
    ))
    rows.append(timing_row(
        "Complete UAV-side software (request processing + response serialization)",
        "UAV", n, time_samples(
            lambda: process_uav_request(
                request_wire, context, identity, vectors
            ),
            trials,
        ),
        "physical PUF acquisition and transport excluded",
    ))
    rows.append(timing_row(
        "Complete verifier response processing",
        "Verifier", n, time_samples(
            lambda: process_verifier_response(
                response_wire, pending, context, identity
            ),
            trials,
        ),
        "includes deserialization, decapsulation, AEAD, AuthRec, Merkle, signature",
    ))
    rows.append(timing_row(
        "Complete verifier-side software (request + response)",
        "Verifier", n, complete_verifier_samples(
            trials, context, identity, vectors
        ),
        "sum of timed request generation and response processing; UAV time excluded",
    ))
    rows.append(timing_row(
        "Complete end-to-end software (UAV + verifier)",
        "Both", n, complete_end_to_end_samples(
            trials, context, identity, vectors
        ),
        "request + UAV processing + verifier processing; transport and physical PUF excluded",
    ))

    sizes = [
        {
            "message": "Verifier request",
            "n": n,
            "serialized_bytes": len(request_wire),
            "encoding": "exact write_message-compatible indented UTF-8 JSON",
        },
        {
            "message": "UAV response",
            "n": n,
            "serialized_bytes": len(response_wire),
            "encoding": "exact write_message-compatible indented UTF-8 JSON",
        },
        {
            "message": "Decrypted UAV payload",
            "n": n,
            "serialized_bytes": len(details["plaintext"]),
            "encoding": "canonical compact UTF-8 JSON before Ascon-AEAD",
        },
    ]
    return rows, sizes


def print_rows(rows: list[dict]) -> None:
    columns = ("operation", "side", "n", "mean_ms", "std_ms")
    widths = {
        column: max(len(column), max(len(str(row[column])) for row in rows))
        for column in columns
    }
    print("  ".join(column.ljust(widths[column]) for column in columns))
    print("  ".join("-" * widths[column] for column in columns))
    for row in rows:
        print("  ".join(str(row[column]).ljust(widths[column]) for column in columns))


def write_outputs(rows: list[dict], sizes: list[dict], suffix: str,
                  vector_source: str, n_values: list[int], trials: int) -> None:
    timing_path = os.path.join(HERE, f"results_final_protocol_timing{suffix}.csv")
    size_path = os.path.join(HERE, f"results_final_protocol_sizes{suffix}.csv")
    availability_path = os.path.join(
        HERE, f"results_final_protocol_availability{suffix}.csv"
    )
    metadata_path = os.path.join(
        HERE, f"results_final_protocol_metadata{suffix}.json"
    )

    with open(timing_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "operation", "side", "n", "mean_ms", "std_ms", "min_ms",
            "max_ms", "trials", "notes",
        ])
        writer.writeheader()
        writer.writerows(rows)
    with open(size_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "message", "n", "serialized_bytes", "encoding",
        ])
        writer.writeheader()
        writer.writerows(sizes)

    availability = [
        {
            "quantity": "Physical PUF acquisition latency",
            "status": "unavailable",
            "reason": "No live physical PUF required or attached; vectors supplied before timer",
        },
        {
            "quantity": "Transport latency",
            "status": "not measured",
            "reason": "File serialization measured; no radio/network transport in prototype",
        },
        {
            "quantity": "Energy",
            "status": "not measured",
            "reason": "Requires external power instrumentation",
        },
    ]
    with open(availability_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["quantity", "status", "reason"]
        )
        writer.writeheader()
        writer.writerows(availability)

    metadata = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "crypto_backend": "Ascon-Hash256 / Ascon-AEAD128 via native ascon-c",
        "ml_dsa": ML_DSA_ALG,
        "ml_kem": ML_KEM_ALG,
        "n_values": n_values,
        "trials": trials,
        "warmup_runs_discarded": 1,
        "puf_vector_source": vector_source,
        "puf_vector_channels": ["S1", "S2"],
        "puf_acquisition_latency": "unavailable",
        "transport_latency": "not measured",
        "energy": "not measured",
    }
    with open(metadata_path, "w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)

    for path in (timing_path, size_path, availability_path, metadata_path):
        print(f"Wrote {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Final protocol software-latency and wire-size benchmark"
    )
    parser.add_argument("--n", type=int, nargs="+", default=None)
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    parser.add_argument("--puf-vectors", default=None)
    args = parser.parse_args()

    n_values = args.n if args.n is not None else DEFAULT_N_VALUES
    if args.trials < 1:
        parser.error("--trials must be at least 1")
    if any(n < 1 for n in n_values):
        parser.error("all --n values must be at least 1")

    vectors, vector_source = load_puf_vectors(args.puf_vectors)
    is_default = (
        n_values == DEFAULT_N_VALUES
        and args.trials == DEFAULT_TRIALS
        and args.puf_vectors is not None
    )
    suffix = "" if is_default else "_quicktest"

    print("=" * 96)
    print("FINAL PROTOCOL REMEASUREMENT")
    print("=" * 96)
    print(f"platform: {platform.platform()}")
    print("crypto: Ascon-Hash256 / Ascon-AEAD128 (native ascon-c)")
    print(f"PUF vectors: {vector_source}")
    print("physical PUF acquisition latency: UNAVAILABLE (not timed)")
    print(f"n values: {n_values}; trials: {args.trials}; one warmup discarded")
    if not is_default:
        print("output class: quicktest (real report requires default n/trials + supplied vectors)")
    print()

    identity = build_identity(vectors)
    all_rows = []
    all_sizes = []
    for n in n_values:
        print(f"Benchmarking n={n} ...")
        rows, sizes = benchmark_context(n, args.trials, identity, vectors)
        all_rows.extend(rows)
        all_sizes.extend(sizes)

    print()
    print_rows(all_rows)
    print()
    for size in all_sizes:
        print(
            f"{size['message']} (n={size['n']}): "
            f"{size['serialized_bytes']} bytes"
        )
    print()
    write_outputs(
        all_rows, all_sizes, suffix, vector_source, n_values, args.trials
    )


if __name__ == "__main__":
    main()
