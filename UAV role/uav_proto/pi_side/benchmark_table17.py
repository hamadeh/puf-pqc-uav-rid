"""
benchmark_table17.py

The Table 17 latency harness. Produces the four rows currently marked
"[measure]" in your manuscript's Table 17:

  1. Majority voting, BCH reconstruction, and 256-bit extraction
  2. One Merkle-root generation, n=1024 and n=16384
  3. Pre-flight root activation, n=1024 and n=16384
  4. On-demand authentication (Algorithm 5+6 combined, UAV-side,
     Profile P), n=1024 and n=16384

Run ON THE RASPBERRY PI 5 (this is pi_side/). Every operation is timed
with time.perf_counter(), the first trial of each operation is
discarded as warmup, and 30 timed trials are kept, matching Table 17's
own stated methodology ("30 Raspberry Pi trials per software
operation").

RELATIONSHIP TO THE EXISTING CODEBASE: this script was originally built
standalone, before shared/fuzzy_extractor.py and shared/puf_emulated.py
implemented Table 11/14/17's actual construction (a 1023-bit RO-PUF
response vector, majority-voted from 9 reads per challenge, BCH(1023,
943,17), and a seeded 256-bit Toeplitz extractor: majority_vote.py,
puf_pipeline_1023.py, toeplitz_extractor.py). A later alignment pass
wired that same pipeline into fuzzy_extractor.py for the live protocol
(Phase 2/3/4), so this script and the live protocol now share the
identical underlying pipeline -- this script still builds its own
identity/Merkle-root/verifier-request scaffolding directly (rather than
importing the phase scripts) so it can run as a standalone benchmark
without a full multi-machine enrollment first, but rows 2-4's Merkle
leaf construction and Algorithm 6 transcript hash match
uav_phase2_enroll_request.py / uav_phase4_session_and_respond.py
exactly, so the timings are representative of what Phase 2/3/4 actually
run, not a diverged construction.

ROW SCOPE: row 1 times ONLY majority-vote + BCH + Toeplitz, matching
its literal name -- synthetic raw-read generation is deliberately
outside the timed region (see run_row1()'s docstring for a real
measurement-validity bug this caught). Rows 3 and 4 (root activation,
on-demand authentication) DO include synthetic PUF-reacquisition inside
their timed region, and that's correct, not an oversight: Algorithm 3
and Algorithm 6 both include a PUF-reacquisition step as part of the
operation being measured, so activation/authentication latency
genuinely includes it. The synthetic-vs-HSpice caveat below still
applies to that portion of rows 3/4's timing.

CO-SIMULATION BOUNDARY, the one rule that matters most here: row 1's
input (nine raw comparator reads per challenge, 1023 challenges) is
NOT HSpice data. No HSpice output exists in this repository to import
(see the module docstring in majority_vote.py). This script generates
SYNTHETIC raw reads of the identical shape purely so the Toeplitz/BCH/
majority-vote CODE PATH can be timed on real Pi hardware; the specific
bit values carry no entropy claim whatsoever and must never be read as
a PUF measurement. This is safe to do for a pure software-latency
benchmark (BCH decode cost is governed by the code parameters and the
actual error count drawn, not by where the bits came from), but it
would NOT be safe for Task C's entropy/uniqueness/BER analysis, which
is exactly why that analysis is a separate script driven by real
HSpice output, not this one.

CRYPTO BACKEND CAVEAT: shared/crypto_primitives.py currently ships as
an explicit "TEMPORARY VERSION using hashlib" (SHA-256 in place of
Ascon-Hash256, and an insecure XOR stand-in in place of Ascon-AEAD128)
per that file's own module docstring; a real ctypes-backed Ascon
implementation exists alongside it as crypto_primitives.py.bak. This
script does not modify that choice; it imports crypto_primitives as-is
and PRINTS which backend is live before running, and records that in
the CSV/LaTeX output, so results are self-documenting about which
backend produced them. If you want Table 17 to reflect Ascon-Hash256/
Ascon-AEAD128 timings (matching what Table 11 states the implementation
uses), restore crypto_primitives.py from the .bak first.

USAGE:
    python3 benchmark_table17.py
        Runs the real paper scale: n in {1024, 16384}, 30 trials.

    python3 benchmark_table17.py --n 16 --trials 3
        Quick smoke test; writes to *_quicktest files so it can never
        be mistaken for a real result.

OUTPUT:
    results_table17_timing.csv   raw per-operation stats
    results_table17_rows.tex     LaTeX rows, ready to paste into
                                  Table 17 in place of "[measure]"
"""

import sys
import os
import time
import platform
import statistics
import secrets
import csv
import argparse
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
sys.path.insert(0, os.path.dirname(__file__))

import protocol_common as pc
import crypto_primitives as cp
import merkle
import majority_vote
import puf_pipeline_1023 as pp
import toeplitz_extractor
import tuple_hash256

import oqs

ML_DSA_ALG = "ML-DSA-65"
ML_KEM_ALG = "ML-KEM-768"
DEFAULT_TRIALS = 30
DEFAULT_N_VALUES = [1024, 16384]
UAV_CTX = b"uav-001"

# post-majority BER target for synthetic raw-read generation: small and
# nonzero so BCH decode exercises real (light) error correction rather
# than a trivially error-free path, without claiming any entropy
# properties for the resulting bits. See module docstring.
_SYNTH_PRE_MAJORITY_FLIP_PROB = 0.06


# ---------------------------------------------------------------------
# Crypto backend detection (for the printed/recorded caveat)
# ---------------------------------------------------------------------

def detect_crypto_backend() -> str:
    doc = (cp.__doc__ or "")
    if "TEMPORARY" in doc or "hashlib" in doc.lower():
        return "PLACEHOLDER (SHA-256 hash / insecure XOR AEAD, not Ascon)"
    return "Ascon-Hash256 / Ascon-AEAD128 (ctypes, ascon-c)"


# ---------------------------------------------------------------------
# Synthetic raw-read generation for row 1 (see module docstring)
# ---------------------------------------------------------------------

def synth_raw_reads(true_bits: list) -> list:
    """
    1023 challenges x 9 reads, each read independently flipped from the
    challenge's true bit with probability _SYNTH_PRE_MAJORITY_FLIP_PROB.
    NOT HSpice data; see module docstring.

    Uses `random`, not `secrets`: this is synthetic timing-benchmark
    input with no security purpose, and secrets.randbelow()'s CSPRNG
    overhead measurably matters here -- called
    NUM_CHALLENGES * READS_PER_CHALLENGE = 9207 times per call, an
    earlier version using secrets.randbelow() added ~80-110ms of pure
    data-generation overhead on top of the few milliseconds the actual
    operations being benchmarked take, enough to distort every row that
    calls this function.
    """
    import random as _random
    reads = []
    for bit in true_bits:
        row = [
            bit ^ (1 if _random.random() < _SYNTH_PRE_MAJORITY_FLIP_PROB else 0)
            for _ in range(majority_vote.READS_PER_CHALLENGE)
        ]
        reads.append(row)
    return reads


def random_true_bits() -> list:
    return [secrets.randbelow(2) for _ in range(majority_vote.NUM_CHALLENGES)]


# ---------------------------------------------------------------------
# Timing helpers (same convention as evaluate_protocol.py)
# ---------------------------------------------------------------------

def timed_trials(fn, trials: int) -> list:
    fn()  # warmup, discarded
    samples = []
    for _ in range(trials):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        samples.append((t1 - t0) * 1000)  # ms
    return samples


def stats_row(name: str, n, samples: list) -> dict:
    return {
        "operation": name,
        "n": n,
        "mean_ms": round(statistics.mean(samples), 4),
        "std_ms": round(statistics.pstdev(samples), 4),
        "min_ms": round(min(samples), 4),
        "max_ms": round(max(samples), 4),
        "trials": len(samples),
    }


# ---------------------------------------------------------------------
# Shared setup: one PUF-rooted identity, reused across n values
# ---------------------------------------------------------------------

def build_uav_identity():
    """
    Runs the majority-vote/BCH/Toeplitz pipeline once (enrollment-style,
    untimed here) to get a stable K_PUF -> S1, S2, PK_i/SK_i, matching
    Eq. (6)/(7). Also builds a TA and a verifier so Phase 4 can be
    exercised against a real signed request.
    """
    import seeded_ml_dsa

    true_bits = random_true_bits()
    enroll_reads = synth_raw_reads(true_bits)
    k_puf, bch_ecc, toeplitz_seed = pp.fe_gen_1023(enroll_reads)

    s1 = cp.kdf(k_puf, pc.TAG_ML_DSA, UAV_CTX)
    s2 = cp.kdf(k_puf, pc.TAG_MERKLE_ROOT, UAV_CTX)  # domain-separated from S1
    pk_i, sk_i = seeded_ml_dsa.seeded_keygen(ML_DSA_ALG, s1)
    kc_i = cp.hash_bytes(pk_i)

    with oqs.Signature(ML_DSA_ALG) as ta_signer:
        pk_ta = ta_signer.generate_keypair()
        sk_ta = ta_signer.export_secret_key()

    with oqs.Signature(ML_DSA_ALG) as vj_signer:
        pk_vj = vj_signer.generate_keypair()
        sk_vj = vj_signer.export_secret_key()

    validity_j = {"start": "2026-01-01T00:00:00Z", "end": "2026-12-31T23:59:59Z"}
    cert_payload = (
        b"verifier-001" + pk_vj + b"test-deployment" +
        json.dumps(validity_j, sort_keys=True).encode("utf-8")
    )
    with oqs.Signature(ML_DSA_ALG, sk_ta) as ta_signer:
        cert_sig = ta_signer.sign(cert_payload)

    cert_vj = {
        "vid_j": "verifier-001", "pk_vj": pk_vj, "scope_j": "test-deployment",
        "validity_j": validity_j, "signature": cert_sig,
    }

    return {
        "true_bits": true_bits, "k_puf": k_puf, "bch_ecc": bch_ecc,
        "toeplitz_seed": toeplitz_seed, "s1": s1, "s2": s2,
        "pk_i": pk_i, "sk_i": sk_i, "kc_i": kc_i,
        "pk_ta": pk_ta, "sk_ta": sk_ta, "sk_vj": sk_vj, "cert_vj": cert_vj,
    }


def build_merkle_root(n: int, s2: bytes, root_nonce: bytes, k: int, flight_ctx_bytes: bytes):
    """
    Matches the now-corrected production construction (uav_phase2_
    enroll_request.py / evaluate_protocol.py): PID includes FlightCtx_k
    (Algorithm 1 line 17), and leaves use merkle.leaf_hash() (H384/
    TupleHash, Eq. 13) rather than the plain H256 hash this benchmark
    used before that alignment pass, so this row's timing reflects what
    Phase 2/3 actually run, not a since-superseded construction.
    """
    seed_k = cp.kdf(s2, root_nonce, k.to_bytes(4, "big"), pc.TAG_MERKLE_ROOT)
    leaves = []
    for j in range(n):
        j_bytes = j.to_bytes(4, "big")
        x_kj = cp.kdf(seed_k, j_bytes, pc.TAG_INTERVAL_SECRET)
        pid_kj = cp.hash_bytes(
            pc.TAG_RID + x_kj + j_bytes + root_nonce + flight_ctx_bytes
        )[:16]
        leaf = merkle.leaf_hash(pid_kj, j, root_nonce, flight_ctx_bytes)
        leaves.append(leaf)
    levels = merkle.build_tree(leaves)
    return merkle.root(levels), levels


def build_verifier_request(n: int, cert_vj: dict, sk_vj: bytes, scope: str):
    """One ReqAuthWire + sigma_Vj, matching Table 4 / Algorithm 5 steps 1-3."""
    with oqs.KeyEncapsulation(ML_KEM_ALG) as kem:
        ek_vj = kem.generate_keypair()
        dk_vj = kem.export_secret_key()

    n_v = secrets.token_bytes(16)
    req_auth = {
        "cert_vj": cert_vj, "ek_vj": ek_vj, "n_v": n_v,
        "ts_v": time.time(), "scope_j": scope, "v": 1,
    }
    req_auth_bytes = pc.canonical_json_bytes(req_auth)
    h_req_auth = cp.hash_bytes(req_auth_bytes)
    with oqs.Signature(ML_DSA_ALG, sk_vj) as signer:
        sigma_vj = signer.sign(h_req_auth)

    return req_auth, sigma_vj, h_req_auth, ek_vj, dk_vj


# ---------------------------------------------------------------------
# Per-n benchmark
# ---------------------------------------------------------------------

def run_timing_for_n(n: int, trials: int, identity: dict) -> list:
    rows = []

    scope = "test-deployment"
    flight_ctx = {"k": 0, "delta_t": 1, "n": n, "scope": scope,
                  "validity": {"start": "x", "end": "y", "max_intervals": n, "region": "r"}}
    flight_ctx_bytes = pc.canonical_json_bytes(flight_ctx)

    root_nonce = secrets.token_bytes(16)
    mr_k, levels = build_merkle_root(n, identity["s2"], root_nonce, 0, flight_ctx_bytes)
    active_state = {
        j: {"pid": levels[0][j], "auth_path": merkle.auth_path(levels, j)}
        for j in range(n)
    }
    pids_list = [levels[0][j] for j in range(n)]

    # ---- Op 2: One Merkle-root generation ----
    rows.append(stats_row(
        f"One Merkle-root generation, n={n}", n,
        timed_trials(lambda: build_merkle_root(
            n, identity["s2"], secrets.token_bytes(16), 0, flight_ctx_bytes), trials)))

    # ---- Op 3: Pre-flight root activation (Algorithm 3) ----
    def activation():
        noisy_bits = list(identity["true_bits"])
        reads = synth_raw_reads(noisy_bits)  # same bits: activation re-derives, not enrollment noise
        k_puf = pp.fe_rec_1023(reads, identity["bch_ecc"], identity["toeplitz_seed"])
        s2_local = cp.kdf(k_puf, pc.TAG_MERKLE_ROOT, UAV_CTX)
        recomputed_mr, _ = build_merkle_root(n, s2_local, root_nonce, 0, flight_ctx_bytes)
        return recomputed_mr == mr_k
    rows.append(stats_row(f"Pre-flight root activation, n={n}", n, timed_trials(activation, trials)))

    # ---- Op 4: On-demand authentication (Algorithm 5+6 combined, UAV side, Profile P) ----

    def on_demand_auth():
        req_auth, sigma_vj, h_req_auth, ek_vj, dk_vj = build_verifier_request(
            n, identity["cert_vj"], identity["sk_vj"], scope)

        # --- Algorithm 5: verifier authentication + session establishment ---
        cert_vj = req_auth["cert_vj"]
        validity_canonical = json.dumps(cert_vj["validity_j"], sort_keys=True).encode("utf-8")
        cert_payload = (
            cert_vj["vid_j"].encode("utf-8") + cert_vj["pk_vj"] +
            cert_vj["scope_j"].encode("utf-8") + validity_canonical
        )
        with oqs.Signature(ML_DSA_ALG) as verifier:
            assert verifier.verify(cert_payload, cert_vj["signature"], identity["pk_ta"])

        req_auth_bytes = pc.canonical_json_bytes(req_auth)
        h_req_auth_local = cp.hash_bytes(req_auth_bytes)
        with oqs.Signature(ML_DSA_ALG) as verifier:
            assert verifier.verify(h_req_auth_local, sigma_vj, cert_vj["pk_vj"])

        # Profile P: constant-time scan over all n cached pseudonyms
        auth_ref = pids_list[secrets.randbelow(n)]
        found_j = -1
        for jj, pid in enumerate(pids_list):
            match = (pid == auth_ref)
            found_j = jj if (match and found_j == -1) else found_j
        j_index = found_j

        with oqs.KeyEncapsulation(ML_KEM_ALG) as kem:
            ct, ss = kem.encap_secret(ek_vj)
        k_sess_full = cp.kdf(ss, req_auth["n_v"], auth_ref,
                              str(req_auth["ts_v"]).encode("utf-8"),
                              h_req_auth_local, pc.TAG_RID_AUTH)
        k_sess = k_sess_full[:16]
        req_id = pc.compute_req_id(req_auth_bytes)
        nonce16 = pc.compute_aead_nonce(req_id, ct)

        # --- Algorithm 6: PUF-rooted post-quantum authentication ---
        reads = synth_raw_reads(identity["true_bits"])
        k_puf = pp.fe_rec_1023(reads, identity["bch_ecc"], identity["toeplitz_seed"])
        s1_local = cp.kdf(k_puf, pc.TAG_ML_DSA, UAV_CTX)
        import seeded_ml_dsa
        pk_i, sk_i = seeded_ml_dsa.seeded_keygen(ML_DSA_ALG, s1_local)
        assert cp.hash_bytes(pk_i) == identity["kc_i"]

        ts_d = time.time()
        auth_path = active_state[j_index]["auth_path"]
        # T_H, Algorithm 6 step 13: matches uav_phase4_session_and_respond.py's
        # corrected construction (H384/TupleHash, RID-UAV-Auth-v1 tag, full
        # field set), so this row's timing reflects the actual signed
        # transcript, not the simplified H256 construction this benchmark
        # used before that alignment pass.
        t_h = tuple_hash256.tuple_hash256(
            pc.TAG_AUTH_TRANSCRIPT, auth_ref, auth_ref, j_index,
            mr_k, root_nonce, flight_ctx_bytes,
            req_auth["n_v"], str(ts_d).encode("utf-8"), ct, h_req_auth_local,
        )
        with oqs.Signature(ML_DSA_ALG, sk_i) as signer:
            sigma_d = signer.sign(t_h)

        payload_s = {
            "auth_ref": auth_ref, "pid": auth_ref, "j": j_index, "root_nonce": root_nonce,
            "flight_ctx": flight_ctx, "auth_path": auth_path, "mr_k": mr_k, "ts_d": ts_d,
            "sigma_d": sigma_d,
        }
        plaintext = pc.canonical_json_bytes(payload_s)
        ad = pc.canonical_json_bytes({
            "req_id": req_id, "ct": ct, "n_a": nonce16, "h_req_auth": h_req_auth_local,
        })
        ciphertext = cp.aead_encrypt(k_sess, nonce16, ad, plaintext)
        return ciphertext

    rows.append(stats_row(f"On-demand authentication, n={n}", n, timed_trials(on_demand_auth, trials)))

    return rows


def run_row1(trials: int) -> dict:
    """
    Op 1: majority voting, BCH reconstruction, and 256-bit extraction.

    Read generation is deliberately OUTSIDE the timed region: Table 17's
    row name is "Majority voting, BCH reconstruction, and 256-bit
    extraction", not data generation -- the raw comparator reads are
    this row's input, not part of what it measures (the paper's own
    HSpice-generation row is the separate entry accounting for
    acquisition time). An earlier version of this function timed
    synth_raw_reads() together with fe_rec_1023(), which added ~80-110ms
    of pure Python data-generation overhead on top of fe_rec_1023's
    actual ~2ms cost -- a measurement-validity bug, not just a slow
    benchmark; fresh reads are still drawn every trial, just untimed.
    """
    identity = build_uav_identity()

    def one_trial() -> float:
        reads = synth_raw_reads(identity["true_bits"])
        t0 = time.perf_counter()
        pp.fe_rec_1023(reads, identity["bch_ecc"], identity["toeplitz_seed"])
        t1 = time.perf_counter()
        return (t1 - t0) * 1000

    one_trial()  # warmup, discarded
    samples = [one_trial() for _ in range(trials)]
    return stats_row("Majority voting, BCH reconstruction, and 256-bit extraction", "-", samples), identity


# ---------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------

def print_table(rows: list, columns: list):
    widths = {c: max(len(c), max((len(str(r[c])) for r in rows), default=0)) for c in columns}
    header = "  ".join(c.ljust(widths[c]) for c in columns)
    print(header)
    print("-" * len(header))
    for r in rows:
        print("  ".join(str(r[c]).ljust(widths[c]) for c in columns))


def write_latex_rows(rows: list, path: str, backend_caveat: str):
    with open(path, "w") as f:
        f.write(f"% Generated by benchmark_table17.py\n")
        f.write(f"% Crypto backend live at benchmark time: {backend_caveat}\n")
        f.write(f"% Row 1 input: synthetic same-shaped raw reads, NOT HSpice data (see module docstring)\n")
        for r in rows:
            op = r["operation"].replace("_", r"\_")
            f.write(f"{op} & {r['mean_ms']:.4f} & {r['std_ms']:.4f} \\\\\n")


def main():
    parser = argparse.ArgumentParser(description="Table 17 latency benchmark harness.")
    parser.add_argument("--n", type=int, nargs="+", default=None)
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    args = parser.parse_args()

    n_values = args.n if args.n is not None else DEFAULT_N_VALUES
    trials = args.trials
    is_default_run = (n_values == DEFAULT_N_VALUES and trials == DEFAULT_TRIALS)
    suffix = "" if is_default_run else "_quicktest"

    backend = detect_crypto_backend()
    print("=" * 100)
    print("TABLE 17 LATENCY BENCHMARK")
    print("=" * 100)
    print(f"  platform: {platform.platform()}")
    print(f"  crypto backend (crypto_primitives.py, live now): {backend}")
    print(f"  n values: {n_values}, trials: {trials}")
    if not is_default_run:
        print(f"  NOTE: not the paper's default scale (n={DEFAULT_N_VALUES}, trials={DEFAULT_TRIALS})")
    print()

    all_rows = []

    print("Row 1: majority voting, BCH reconstruction, 256-bit extraction ...")
    row1, identity = run_row1(trials)
    all_rows.append(row1)
    print_table([row1], ["operation", "mean_ms", "std_ms", "min_ms", "max_ms", "trials"])

    for n in n_values:
        print(f"\nn={n} ...")
        rows = run_timing_for_n(n, trials, identity)
        all_rows.extend(rows)
        print_table(rows, ["operation", "n", "mean_ms", "std_ms", "min_ms", "max_ms", "trials"])

    timing_csv = os.path.join(os.path.dirname(__file__), f"results_table17_timing{suffix}.csv")
    with open(timing_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["operation", "n", "mean_ms", "std_ms", "min_ms", "max_ms", "trials"])
        writer.writeheader()
        writer.writerows(all_rows)

    latex_path = os.path.join(os.path.dirname(__file__), f"results_table17_rows{suffix}.tex")
    write_latex_rows(all_rows, latex_path, backend)

    print(f"\n{'=' * 100}")
    print(f"Wrote {timing_csv}")
    print(f"Wrote {latex_path}")
    print(f"\nCrypto backend used for these numbers: {backend}")
    print("Row 1 used synthetic same-shaped raw-read data, not HSpice output (see module docstring).")


if __name__ == "__main__":
    main()
