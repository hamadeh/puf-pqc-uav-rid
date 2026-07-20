"""
evaluate_protocol.py

NOTICE: this is the historical Table 4/6/7 harness.  Measurements of the
final Profile-P implementation belong in benchmark_final_protocol.py, which
adds full PIDIndex-aware activation, supplied-vector reconstruction, final
wire-format request/response sizes, primitive timings, and complete
UAV/verifier software latency.  Keep this script for reproducing the older
paper tables; do not use its activation or authentication rows as final
protocol measurements.

The single script to run on the Pi 5 to get everything your paper's
Table 4, 6, and 7 need. Supersedes benchmark_phases.py (still there, but
this is the one to use going forward): adds automatic system-info
collection, message/storage SIZE measurements alongside timing, runs
both n=1024 and n=16384 in one invocation, and writes a CSV file you can
paste straight into a spreadsheet or your paper's tables.

USAGE (on the Pi 5, after the one-time setup in shared/build_ascon_libs.sh
has been run):

    python3 evaluate_protocol.py
        Runs at your paper's real parameters: n=1024 and n=16384, 30
        trials each. This is what you want for the numbers you actually
        report.

    python3 evaluate_protocol.py --n 16 --trials 3
        Quick verification run, e.g. to confirm everything works before
        committing to the full run. Writes to separate
        results_timing_quicktest.csv / results_sizes_quicktest.csv files
        so a quick check can never be mistaken for, or accidentally
        overwrite, your real results.

Takes well under a minute total at the default scale given how fast the
C-backed primitives are now.

OUTPUT:
  - Printed tables to the screen (timing + sizes + system info)
  - results_timing.csv   (one row per operation per n)
  - results_sizes.csv    (one row per message/storage object)

WHAT THIS DOES NOT MEASURE, and why, read before using these numbers:
  - PUF evaluation timing: this is emulator overhead (see
    puf_emulated.py's docstring), not real RO-PUF latency. Reported
    separately and labeled, do not use it as a hardware PUF number.
  - Energy (mJ): needs real power instrumentation (current probe and
    oscilloscope, or at minimum a USB in-line power meter) on the Pi's
    supply rail. Nothing here estimates this from CPU time; that would
    be exactly the kind of invented number you shouldn't put in a paper.

ALIGNED WITH THE PAPER (this pass): PUF acquisition/extraction now runs
the real ChallengeSchedule -> MajorityPUF(9 reads) -> FE.Gen/FE.Rec
(BCH(1023,943,17)) -> Toeplitz-256 pipeline instead of a single
noiseless puf_response() call; Merkle leaves include FlightCtx_k and
use merkle.leaf_hash() (H384/TupleHash) instead of the old H256
construction with no FlightCtx binding. The "Lightweight authentication"
row is gone: the paper's final Algorithm 5+6 has no lower-assurance
branch, so there is nothing to measure there anymore; what used to be
"Strong authentication" is now simply the on-demand authentication
compute cost, since it's the only mode.
"""

import sys
import os
import time
import platform
import statistics
import secrets
import csv
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
sys.path.insert(0, os.path.dirname(__file__))

import protocol_common as pc
import crypto_primitives as cp
import merkle
import puf_emulated
import challenge_schedule
import fuzzy_extractor
import seeded_ml_dsa
import tuple_hash256

import oqs

ML_DSA_ALG = "ML-DSA-65"
ML_KEM_ALG = "ML-KEM-768"
DEFAULT_TRIALS = 30
DEFAULT_N_VALUES = [1024, 16384]
UAV_CTX = b"uav-001"


# ---------------------------------------------------------------------
# System info (for Table 4)
# ---------------------------------------------------------------------

def collect_system_info() -> dict:
    info = {
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown (see /proc/cpuinfo below)",
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "liboqs_version": oqs.oqs_version(),
    }
    # Linux-specific, more precise CPU model than platform.processor()
    # often returns on ARM boards
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("model name") or line.lower().startswith("hardware"):
                    info["cpuinfo_model"] = line.split(":", 1)[1].strip()
                    break
    except FileNotFoundError:
        info["cpuinfo_model"] = "not available (not Linux, or file missing)"
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    info["mem_total"] = line.split(":", 1)[1].strip()
                    break
    except FileNotFoundError:
        info["mem_total"] = "not available"
    return info


# ---------------------------------------------------------------------
# Timing helpers
# ---------------------------------------------------------------------

def timed_trials(fn, trials: int) -> list:
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


def build_merkle_root(n: int, S2: bytes, root_nonce: bytes, k: int, flight_ctx_bytes: bytes):
    seed_k = cp.kdf(S2, root_nonce, k.to_bytes(4, "big"), pc.TAG_MERKLE_ROOT)
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


# ---------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------

def run_timing_for_n(n: int, trials: int) -> list:
    rows = []
    puf_emulated.reset_store()

    c_seed1, c_seed2 = secrets.token_bytes(32), secrets.token_bytes(32)
    challenges1 = challenge_schedule.challenge_schedule(c_seed1)
    challenges2 = challenge_schedule.challenge_schedule(c_seed2)

    reads1 = puf_emulated.acquire_response_reads(challenges1)
    reads2 = puf_emulated.acquire_response_reads(challenges2)
    S1, HD1 = fuzzy_extractor.fe_gen(reads1)
    S2, HD2 = fuzzy_extractor.fe_gen(reads2)
    seed_sig = cp.kdf(S1, pc.TAG_ML_DSA, UAV_CTX)
    PK_i, SK_i = seeded_ml_dsa.seeded_keygen(ML_DSA_ALG, seed_sig)
    KC_i = cp.hash_bytes(PK_i)
    root_nonce = secrets.token_bytes(16)
    flight_ctx = {"k": 0, "delta_t": 1, "n": n, "scope": "test-deployment",
                  "validity": {"start": "x", "end": "y", "max_intervals": n, "region": "r"}}
    flight_ctx_bytes = pc.canonical_json_bytes(flight_ctx)
    mr_k, levels = build_merkle_root(n, S2, root_nonce, 0, flight_ctx_bytes)

    rows.append(stats_row(
        "PUF response acquisition (EMULATED, not real hardware; "
        "ChallengeSchedule + 9 reads/challenge)", n,
        timed_trials(lambda: puf_emulated.acquire_response_reads(challenges1), trials)))

    rows.append(stats_row(
        "Fuzzy extractor generation (FE.Gen: MajorityPUF + BCH(1023,943,17) + Toeplitz-256)", n,
        timed_trials(lambda: fuzzy_extractor.fe_gen(reads1), trials)))

    rows.append(stats_row(
        "Fuzzy extractor reconstruction (FE.Rec)", n,
        timed_trials(lambda: fuzzy_extractor.fe_rec(reads2, HD2), trials)))

    rows.append(stats_row(
        f"One Merkle-root generation, n={n}", n,
        timed_trials(lambda: build_merkle_root(
            n, S2, secrets.token_bytes(16), 0, flight_ctx_bytes), trials)))

    def activation():
        s2 = fuzzy_extractor.fe_rec(reads2, HD2)
        recomputed_mr, _ = build_merkle_root(n, s2, root_nonce, 0, flight_ctx_bytes)
        return recomputed_mr == mr_k
    rows.append(stats_row(f"Pre-flight root activation, n={n}", n, timed_trials(activation, trials)))

    pids_precomputed = [levels[0][j] for j in range(n)]
    rows.append(stats_row(
        "Routine broadcast identifier selection", n,
        timed_trials(lambda: pids_precomputed[secrets.randbelow(n)], trials)))

    with oqs.KeyEncapsulation(ML_KEM_ALG) as kem:
        ek_vj = kem.generate_keypair()

    def session_establishment():
        with oqs.KeyEncapsulation(ML_KEM_ALG) as kem:
            ct, ss = kem.encap_secret(ek_vj)
        return cp.kdf(ss, secrets.token_bytes(16), secrets.token_bytes(16),
                       b"ts", b"hreq", pc.TAG_RID_AUTH)
    rows.append(stats_row(
        "Verifier auth + session establishment (UAV side)", n,
        timed_trials(session_establishment, trials)))

    j_index = 0
    auth_ref = pids_precomputed[j_index]

    def on_demand_auth_compute():
        s1 = fuzzy_extractor.fe_rec(reads1, HD1)
        seed_sig_local = cp.kdf(s1, pc.TAG_ML_DSA, UAV_CTX)
        pk_i, sk_i = seeded_ml_dsa.seeded_keygen(ML_DSA_ALG, seed_sig_local)
        assert cp.hash_bytes(pk_i) == KC_i
        t_h = tuple_hash256.tuple_hash256(
            pc.TAG_AUTH_TRANSCRIPT, auth_ref, auth_ref, j_index,
            mr_k, root_nonce, flight_ctx_bytes,
            secrets.token_bytes(16), b"ts", b"ct", b"hreq",
        )
        with oqs.Signature(ML_DSA_ALG, sk_i) as signer:
            sigma_d = signer.sign(t_h)
        plaintext = pc.canonical_json_bytes({"sigma_d": sigma_d})
        return cp.aead_encrypt(secrets.token_bytes(16), secrets.token_bytes(16), b"ad", plaintext)
    rows.append(stats_row(
        "On-demand authentication (UAV side compute, incl. key regen)", n,
        timed_trials(on_demand_auth_compute, trials)))

    return rows


def measure_sizes(n: int) -> list:
    """Real serialized sizes of the protocol's actual message/storage objects."""
    rows = []

    with oqs.Signature(ML_DSA_ALG) as tmp:
        pk_sample = tmp.generate_keypair()
        sk_sample = tmp.export_secret_key()
        sig_sample = tmp.sign(b"sample message for size measurement")
    rows.append({"object": "ML-DSA-65 public key (PK_i / PK_TA / PK_Vj)", "n": n, "size_bytes": len(pk_sample)})
    rows.append({"object": "ML-DSA-65 secret key (SK_i)", "n": n, "size_bytes": len(sk_sample)})
    rows.append({"object": "ML-DSA-65 signature (AuthRec, Cert_Vj, sigma_D)", "n": n, "size_bytes": len(sig_sample)})

    with oqs.KeyEncapsulation(ML_KEM_ALG) as kem:
        ek_sample = kem.generate_keypair()
        ct_sample, ss_sample = kem.encap_secret(ek_sample)
    rows.append({"object": "ML-KEM-768 public key (ek_Vj)", "n": n, "size_bytes": len(ek_sample)})
    rows.append({"object": "ML-KEM-768 ciphertext (ct)", "n": n, "size_bytes": len(ct_sample)})

    puf_emulated.reset_store()
    c_seed1, c_seed2 = secrets.token_bytes(32), secrets.token_bytes(32)
    _, HD1 = fuzzy_extractor.gen_from_seed(c_seed1)
    _, HD2 = fuzzy_extractor.gen_from_seed(c_seed2)
    rows.append({"object": "Fuzzy extractor helper data (HD1 or HD2)", "n": n, "size_bytes": len(HD1)})
    assert len(HD1) == len(HD2)

    # Store_D_i^NV for one root at this n (the actual persisted UAV record)
    root_nonce = secrets.token_bytes(16)
    store_nv_one_root = {
        "root_nonce": root_nonce, "k": 0,
        "flight_ctx": {"n": n, "delta_t": 1, "scope": "test-deployment",
                       "validity": {"start": "x", "end": "y", "max_intervals": n, "region": "r"}},
        "auth_rec_signature": sig_sample,
        "mr_k": secrets.token_bytes(48),  # H384/TupleHash256 output, not 32 bytes
    }
    serialized = pc.canonical_json_bytes(store_nv_one_root)
    rows.append({"object": f"Store_D_i^NV, one root record, n={n}", "n": n, "size_bytes": len(serialized)})

    # Interval journal, per root (Eq. 24 / Table 11), independent of n
    rows.append({"object": "Interval journal file, one root (2x4096-byte slots)",
                 "n": n, "size_bytes": 8192})

    return rows


def print_table(rows: list, columns: list):
    widths = {c: max(len(c), max((len(str(r[c])) for r in rows), default=0)) for c in columns}
    header = "  ".join(c.ljust(widths[c]) for c in columns)
    print(header)
    print("-" * len(header))
    for r in rows:
        print("  ".join(str(r[c]).ljust(widths[c]) for c in columns))


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate the protocol's UAV-side operations. "
                    "Defaults to your paper's real parameters (n=1024 and "
                    "n=16384, 30 trials); override with --n and --trials "
                    "for a quick verification run first."
    )
    parser.add_argument("--n", type=int, nargs="+", default=None,
                        help="interval count(s) to test, e.g. --n 16 "
                             "for a quick check, or --n 1024 16384 for "
                             "the real paper numbers (this is the default "
                             "if you don't pass --n at all)")
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS,
                        help=f"trials per operation (default: {DEFAULT_TRIALS})")
    args = parser.parse_args()

    n_values = args.n if args.n is not None else DEFAULT_N_VALUES
    trials = args.trials

    if n_values != DEFAULT_N_VALUES or trials != DEFAULT_TRIALS:
        print(f"NOTE: running with n={n_values}, trials={trials}, this is "
              f"NOT the default paper scale (n={DEFAULT_N_VALUES}, "
              f"trials={DEFAULT_TRIALS}). Fine for a quick check; rerun "
              f"with no arguments when you want the real numbers.\n")

    print("=" * 100)
    print("SYSTEM INFO (for Table 4)")
    print("=" * 100)
    info = collect_system_info()
    for k, v in info.items():
        print(f"  {k}: {v}")

    all_timing_rows = []
    all_size_rows = []

    for n in n_values:
        print(f"\n{'=' * 100}\nTIMING, n={n}, {trials} trials per operation\n{'=' * 100}")
        rows = run_timing_for_n(n, trials)
        print_table(rows, ["operation", "mean_ms", "std_ms", "min_ms", "max_ms", "trials"])
        all_timing_rows.extend(rows)

        print(f"\n{'-' * 100}\nMESSAGE / STORAGE SIZES, n={n}\n{'-' * 100}")
        size_rows = measure_sizes(n)
        print_table(size_rows, ["object", "size_bytes"])
        all_size_rows.extend(size_rows)

    is_default_run = (n_values == DEFAULT_N_VALUES and trials == DEFAULT_TRIALS)
    suffix = "" if is_default_run else "_quicktest"

    timing_csv = os.path.join(os.path.dirname(__file__), f"results_timing{suffix}.csv")
    with open(timing_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["operation", "n", "mean_ms", "std_ms", "min_ms", "max_ms", "trials"])
        writer.writeheader()
        writer.writerows(all_timing_rows)

    sizes_csv = os.path.join(os.path.dirname(__file__), f"results_sizes{suffix}.csv")
    with open(sizes_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["object", "n", "size_bytes"])
        writer.writeheader()
        writer.writerows(all_size_rows)

    print(f"\n{'=' * 100}")
    print(f"Wrote {timing_csv}")
    print(f"Wrote {sizes_csv}")
    print("\nReminders before using these numbers in your paper:")
    print("  - PUF response acquisition row is emulator overhead, not real RO-PUF latency.")
    print("  - Energy (mJ): not measured here, needs real power instrumentation.")
    print("  - These numbers reflect whichever crypto_primitives.py backend is live "
          "(placeholder or real Ascon); check that file before reporting Table 4/6/7.")


if __name__ == "__main__":
    main()
