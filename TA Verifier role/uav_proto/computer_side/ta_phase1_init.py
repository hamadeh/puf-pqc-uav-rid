"""
ta_phase1_init.py

Runs on: your computer (TA role).
Implements: Phase 1, System Initialization (Section III.C / Eq. system_params,
eq:ta_keygen). This is the ONLY script for Phase 1, the protocol has no
UAV or verifier action in this phase, both first appear in Phase 2.

Run this once. It produces two files:

  out/ta_public_params.json
      Safe to copy to the Pi 5 and to any verifier machine. Contains
      PK_TA and the public Params/domain-separation tags every device
      needs to agree on. This is your simulated "distribution" step
      (Algorithm listing: "Distribute PK_TA"), copy this file by hand
      (USB, scp, SD card) to the Pi before running any Phase 2 UAV code.

  out/ta_secret_DO_NOT_SHARE.json
      SK_TA. Stays on this machine. Never copy this file anywhere. It's
      named this way on purpose, so it's obvious at a glance in a
      directory listing which file is safe to move and which isn't.
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))
import protocol_common as pc

import oqs

OUT_DIR = os.path.join(os.path.dirname(__file__), "out")


def main():
    parser = argparse.ArgumentParser(description="TA system initialization")
    parser.add_argument("--n", type=int, default=pc.N_INTERVALS,
                        help="intervals per Merkle root (power of two)")
    parser.add_argument("--m", type=int, default=pc.M_ROOTS,
                        help="authorized roots per enrollment cycle")
    args = parser.parse_args()
    if args.n < 1 or args.n & (args.n - 1):
        parser.error("--n must be a positive power of two")
    if args.m < 1:
        parser.error("--m must be positive")

    print(f"Phase 1: System Initialization (TA)")
    print(f"Protocol parameters: n={args.n}, m={args.m}")
    print(f"Generating {pc.ML_DSA_ALG} signing key pair for the TA...")

    with oqs.Signature(pc.ML_DSA_ALG) as signer:
        pk_ta = signer.generate_keypair()
        sk_ta = signer.export_secret_key()

    print(f"  PK_TA: {len(pk_ta)} bytes")
    print(f"  SK_TA: {len(sk_ta)} bytes")

    # --- Public output: safe to copy to the Pi / verifier machines ---
    public_params = {
        "pk_ta": pk_ta,
        "ml_dsa_alg": pc.ML_DSA_ALG,
        "ml_kem_alg": pc.ML_KEM_ALG,
        "delta_t_seconds": pc.DELTA_T_SECONDS,
        "n_intervals": args.n,
        "m_roots": args.m,
        "security_parameter_bits": pc.SECURITY_PARAMETER_BITS,
    }
    public_path = os.path.join(OUT_DIR, "ta_public_params.json")
    pc.write_message(public_path, public_params)
    print(f"\nWrote public params (safe to copy to Pi): {public_path}")

    # --- Secret output: stays on this machine, never copied ---
    secret_params = {"sk_ta": sk_ta}
    secret_path = os.path.join(OUT_DIR, "ta_secret_DO_NOT_SHARE.json")
    pc.write_message(secret_path, secret_params)
    print(f"Wrote TA secret key (DO NOT COPY THIS FILE): {secret_path}")

    print(f"\nNext step: copy {os.path.basename(public_path)} to the Pi 5")
    print("and to any verifier machine, before running Phase 2 scripts.")


if __name__ == "__main__":
    main()
