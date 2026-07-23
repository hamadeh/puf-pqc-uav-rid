# PUF-Rooted Post-Quantum Authentication for Pseudonymous UAV Remote ID

Research prototype and reproducibility artifacts for a PUF-rooted,
post-quantum UAV Remote ID authentication protocol. The implementation splits
the protocol between:

- a Raspberry Pi 5 acting as the UAV;
- an Intel Mac acting as the Trusted Authority (TA) and authorized verifier;
- HSpice circuit/software co-simulation for the modeled 45 nm RO-PUF; and
- a Tamarin model for symbolic protocol analysis.

The cryptographic prototype uses ML-DSA-65, ML-KEM-768, Ascon-Hash256,
Ascon-AEAD128, TupleHash256, a BCH-based fuzzy extractor, a seeded Toeplitz
extractor, and a Merkle commitment over interval pseudonyms.

> **Scientific boundary:** HSpice-derived PUF results are circuit-simulation
> results, not fabricated-silicon measurements. Raspberry Pi timings measure
> software processing and never represent physical PUF acquisition latency.
> Radio/network transport latency and energy are not estimated.

## Repository layout

| Path | Contents |
|---|---|
| `UAV role/uav_proto/` | UAV protocol implementation and Raspberry Pi benchmarks |
| `TA Verifier role/uav_proto/` | TA and verifier implementation for the Intel Mac |
| `Hspice code/` | RO-PUF netlists, 100-process-instance PVT logs, analysis outputs, and response data |
| `Tamarin/` | Separate core-authentication and revocation Tamarin models, proved forms, logs, checksums, and verification evidence |
| `Results/` | Collected Raspberry Pi and analysis result files |

Generated private keys, pending-session state, emulated-PUF state, native
libraries, virtual environments, and vendored dependency trees are intentionally
excluded by `.gitignore`.

## Raspberry Pi 5: quick start

### 1. Clone the repository

```bash
cd ~
git clone https://github.com/hamadeh/A-PUF-Based-Post-Quantum-Authentication-Protocol-for-Pseudonymous-UAV-RID.git
cd A-PUF-Based-Post-Quantum-Authentication-Protocol-for-Pseudonymous-UAV-RID
```

### 2. Install system packages

```bash
sudo apt update
sudo apt install -y \
  build-essential cmake ninja-build git \
  python3 python3-dev python3-venv \
  libssl-dev
```

### 3. Build and install liboqs

```bash
cd "UAV role/uav_proto"
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build \
  -GNinja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_DIST_BUILD=ON
cmake --build liboqs/build --parallel
sudo cmake --install liboqs/build
sudo ldconfig
```

Confirm that the shared library is visible:

```bash
ldconfig -p | grep liboqs
```

### 4. Create the Python environment

```bash
cd ~/A-PUF-Based-Post-Quantum-Authentication-Protocol-for-Pseudonymous-UAV-RID/"UAV role/uav_proto"
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

If the packaged `liboqs-python` binding is unavailable for the Pi, install it
from its official repository:

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git
python3 -m pip install ./liboqs-python
```

### 5. Build the native Ascon libraries

The Ascon binaries are architecture-specific and must be built on the Pi.

```bash
cd ~/A-PUF-Based-Post-Quantum-Authentication-Protocol-for-Pseudonymous-UAV-RID/"UAV role/uav_proto/shared"
git clone --depth 1 https://github.com/ascon/ascon-c.git ascon-c

gcc -O3 -fPIC -shared \
  -Iascon-c/src -Iascon-c \
  -DCRYPTO_NAMESPACE= \
  -DASCON_HASH=1 -DASCON_HASH_RATE=8 -DASCON_HASH_ROUNDS=12 \
  -o libasconhash.so \
  ascon-c/src/hash.c ascon-c/src/printstate.c ascon-c/src/permutations.c

gcc -O3 -fPIC -shared \
  -Iascon-c/src -Iascon-c \
  -DCRYPTO_NAMESPACE= \
  -DASCON_AEAD=1 -DASCON_AEAD_RATE=8 -DASCON_AEAD_ROUNDS=12 \
  -o libasconaead.so \
  ascon-c/src/aead.c ascon-c/src/printstate.c ascon-c/src/permutations.c

python3 -c "import ctypes; ctypes.CDLL('./libasconhash.so'); ctypes.CDLL('./libasconaead.so'); print('Ascon libraries OK')"
```

### 6. Run a small smoke test

```bash
cd ../pi_side
python3 benchmark_final_protocol.py --n 16 --trials 3
```

This uses a deterministic software fixture and writes files ending in
`_quicktest`. It verifies the software path only and makes no PUF entropy or
physical-acquisition claim.

### 7. Run the full Raspberry Pi measurement

The report-scale run uses `n=1024` and `n=16384`, discards one warm-up, and
records 30 trials per operation:

```bash
python3 benchmark_final_protocol.py \
  --puf-vectors ../puf_vectors_stage128.json
```

The command writes:

```text
results_final_protocol_timing.csv
results_final_protocol_sizes.csv
results_final_protocol_availability.csv
results_final_protocol_metadata.json
```

Copy these files into `Results/` when preserving a completed measurement run.
The metadata file must identify the Raspberry Pi platform, the native Ascon
backend, the two PUF-vector channels, `n=[1024,16384]`, and 30 trials.

## Crash-recovery experiment

Run the fault-injection harness on the Raspberry Pi's ext4 microSD filesystem,
not on the Mac:

```bash
cd "UAV role/uav_proto/pi_side"
python3 crash_recovery_harness.py
```

The harness uses disposable interval journals and injects interruption at:

1. before the inactive-slot write;
2. during the slot write;
3. after `fdatasync()` and before transmission; and
4. immediately after transmission.

The required safety result is zero reuse of a previously transmitted
pseudonym. Record the actual microSD model and mount configuration alongside
the results:

```bash
uname -a
python3 --version
cat /proc/device-tree/model; echo
df -T .
mount | grep "$(df . | tail -1 | awk '{print $1}')"
```

## Full protocol workflow

The prototype uses JSON files as a stand-in for transport. Copy each output to
the other role's matching `in/` directory between steps.

### TA initialization (Mac)

```bash
cd "TA Verifier role/uav_proto/computer_side"
python3 ta_phase1_init.py --n 1024
```

Use `--n 16384` for the second report-scale experiment. Phase 1 validates that
`n` is a positive power of two, so switching sizes no longer requires editing
`shared/protocol_common.py`.

Copy `out/ta_public_params.json` to `UAV role/uav_proto/pi_side/in/`.

### UAV enrollment (Pi)

```bash
cd "UAV role/uav_proto/pi_side"
python3 uav_phase2_enroll_request.py
```

Copy `out/uav_root_requests.json` to the TA's `computer_side/in/`, then run:

```bash
python3 ta_phase2_enroll_process.py
```

Copy the TA's `out/ta_authrec_response.json` back to the UAV's `pi_side/in/`,
then run:

```bash
python3 uav_phase2_enroll_finalize.py
```

### Verifier enrollment (Mac)

```bash
cd "TA Verifier role/uav_proto/computer_side"
python3 verifier_phase2_enroll_request.py
python3 ta_phase2_verifier_enroll_process.py
```

### Root activation and broadcast (Pi)

```bash
cd "UAV role/uav_proto/pi_side"
python3 uav_phase3_activate_and_broadcast.py
```

Copy `out/broadcast_log.jsonl` to the verifier's `computer_side/in/`.

### On-demand authentication

On the verifier:

```bash
python3 verifier_phase4_request.py
```

Copy `out/verifier_reqauth.json` to the UAV's `pi_side/in/`, then on the UAV:

```bash
python3 uav_phase4_session_and_respond.py
```

Copy `out/uav_response.json` to the verifier's `computer_side/in/`, then:

```bash
python3 verifier_phase4_process_response.py
```

A successful run ends with:

```text
ACCEPT: signing identity and Merkle root both bound.
```

## Live Wi-Fi unicast experiment

After enrollment, verifier enrollment, and one Phase 3 broadcast, start the
TCP wrapper on the Pi:

```bash
cd "UAV role/uav_proto/pi_side"
python3 uav_tcp_server.py --n 1024
```

Run one discarded warmup and 30 fresh, verified sessions from the Mac:

```bash
cd "TA Verifier role/uav_proto/computer_side"
python3 verifier_tcp_client.py \
  --host PI_IP --port 40444 --n 1024 \
  --warmup 1 --trials 30 --fresh-request --verify-response
```

Repeat the full enrollment and experiment with `n=16384`. Capture the TCP/IP
exchange with `tcpdump` when packet counts, retransmissions, and fragmentation
are required. The synchronized raw CSV/JSON/PCAP datasets, comparison summary,
and LaTeX rows are under `Results/live_unicast/`.

The application RTT timer starts after TCP connection establishment and ends
after reception of the complete response. It includes Wi-Fi transport and UAV
software processing, but excludes request generation and final verifier
processing. It is not isolated radio latency. Packet-capture retransmissions
are TCP observations, not IEEE 802.11 MAC retry counts.

## HSpice RO-PUF artifacts

`Hspice code/` contains the 45 nm modeled RO-PUF netlists, a fixed population
of 100 simulated process instances, PVT logs, and processed CSV/MAT/PNG
outputs. The main population outputs are under:

```text
Hspice code/RO_PUF_PVT_100_results/
```

The committed analysis reports 100 valid simulated process logs, 54 enrolled
instances under the stated margin rule, and all 432 executed non-nominal
reconstructions succeeding for those enrolled instances. These are
co-simulation results only; the remaining 46 simulated instances did not meet
the enrollment criterion, and no fabricated device was measured.

## Tamarin models and verification evidence

The symbolic analysis is separated into two tractable theories:

| Model | Purpose |
|---|---|
| `Tamarin/UAV_RemoteID_Core_Simplified.spthy` | Core Profile-P request authentication, replay resistance, agreement, Merkle leaf/index binding, session-key secrecy, passive storage disclosure, and active-capture negative control |
| `Tamarin/UAV_RemoteID_Revocation_Simplified_v3.spthy` | Revocation-version consistency and fail-closed behavior for root, verifier, and UAV-key revocation |
| `Tamarin/UAV_RemoteID_Core_Simplified_proved.spthy` | Proved/expanded core theory retained with the evidence package |

With Tamarin Prover installed, run the source theories independently:

```bash
tamarin-prover "Tamarin/UAV_RemoteID_Core_Simplified.spthy" --prove
tamarin-prover "Tamarin/UAV_RemoteID_Revocation_Simplified_v3.spthy" --prove
```

`Tamarin/Tamarin_Final_Evidence/` contains the exact model copies, individual
lemma logs, consolidated core/revocation summaries, verification environment,
and SHA-256 manifest from the completed run. The recorded environment used
Tamarin 1.13.0 and Maude 3.5.1 under Linux/WSL2. All selected core and
revocation lemmas were verified; `active_capture_impersonation_reachable` is an
expected negative-control attack trace after active UAV capture.

Verify the evidence bundle's integrity from the repository root:

```bash
sha256sum -c Tamarin/Tamarin_Final_Evidence/SHA256SUMS.txt
```

## Existing results

`Results/results_final_protocol_metadata.json` identifies the committed final
software benchmark as a Raspberry Pi aarch64 run with native Ascon, supplied
PUF vectors, `n=1024` and `n=16384`, 30 recorded trials, and one discarded
warm-up. `Results/live_unicast/` contains the separate live Wi-Fi/TCP
evaluation. Consult each metadata file and availability CSV together with its
timing table; do not reinterpret unavailable physical-PUF or energy quantities
as zero.

## Security and reproducibility notes

- Never commit files named `*_DO_NOT_SHARE.json`.
- Native `.so` files must be rebuilt independently on each architecture.
- Deleting `.puf_store.json` invalidates any enrollment created from that
  emulated device state.
- The JSON file channel is a prototype transport and is not a production wire
  format.
- The BCH Python binding protects a byte-aligned shortened message; see
  `shared/puf_pipeline_1023.py` for the exact capacity disclosure.
- Benchmark input vectors are supplied before timing; physical acquisition is
  excluded by design.

## License and citation

No project license or finalized publication citation is currently declared in
this repository. Add the applicable license and accepted-paper citation before
inviting third-party reuse.
