# Protocol-v1 measurement evidence (2026-07-24)

This directory contains the post-alignment Raspberry Pi 5 software benchmark
and live Wi-Fi/TCP authentication results for protocol version 1. These files
replace manuscript use of the older pre-alignment measurements; they do not
overwrite or relabel the historical raw data elsewhere in `Results/`.

## Raspberry Pi software timing

One warm-up was discarded and 30 trials were recorded per operation.

| Operation | n | Mean (ms) | Sample SD (ms) |
|---|---:|---:|---:|
| Supplied PUF-vector processing + BCH(950,870) + Toeplitz-256 | - | 1.870 | 0.037 |
| Merkle-root generation | 1024 | 74.195 | 0.471 |
| Pre-flight root activation | 1024 | 76.923 | 0.585 |
| UAV on-demand authentication | 1024 | 4.218 | 0.417 |
| Merkle-root generation | 16384 | 1182.802 | 3.370 |
| Pre-flight root activation | 16384 | 1206.367 | 15.447 |
| UAV on-demand authentication | 16384 | 4.471 | 0.554 |

The PUF input vectors were supplied before timing. The reported PUF row is
software reconstruction only and excludes physical PUF acquisition. The
deterministic margin ordering used by the harness is a timing fixture, not an
LTspice or fabricated-silicon measurement.

## Live Wi-Fi/TCP authentication

One warm-up was discarded and 30 fresh, cryptographically verified sessions
were recorded for each Merkle-root size.

| Metric | n=1024 | n=16384 |
|---|---:|---:|
| Application RTT (mean +/- sample SD) | 37.034 +/- 19.410 ms | 33.898 +/- 25.512 ms |
| Resident Pi processing | 17.402 +/- 2.958 ms | 16.619 +/- 2.266 ms |
| Request protocol payload | 10,030 B | 10,030 B |
| Response protocol payload | 5,095 B | 5,291 B |
| Framed TCP application bytes/exchange | 15,149 B | 15,345 B |
| Captured TCP packets/exchange | 26.400 +/- 2.010 | 26.333 +/- 2.264 |
| Data-bearing TCP segments/exchange | 13.533 +/- 1.224 | 13.300 +/- 0.988 |
| TShark retransmission observations | 21 | 12 |
| IPv4 fragments | 0 | 0 |
| Cryptographically accepted | 30/30 | 30/30 |

The `n=1024` curated capture contains the 30 recorded streams filtered from
source streams 48--77. The `n=16384` capture retains warm-up stream 0; recorded
trials are streams 1--30. Packet counts include TCP setup, acknowledgements,
retransmissions, and teardown.

TShark retransmission indicators are TCP-layer observations, not IEEE 802.11
MAC retries or a direct physical packet-loss rate. Zero application failures
does not establish zero physical-layer loss. Captured frame-byte totals use
the capture interface's EN10MB representation and are not Wi-Fi airtime bytes.

The RTT starts immediately before sending the framed request on an established
TCP connection and ends after receiving the complete framed response. It
excludes request generation, connection establishment, final verifier
processing, physical PUF acquisition, and pre-flight Merkle-tree activation.

## Cryptographic configuration

- ML-DSA-65 and ML-KEM-768 through liboqs.
- Ascon-Hash256 and Ascon-AEAD128, NIST SP 800-232.
- TupleHash256 with a 384-bit output for Merkle and transcript hashing.
- Nine-read majority vote, top-950 selection, shortened BCH(950,870), `t=8`,
  and a 950-to-256-bit Toeplitz extractor.

The Pi result metadata records Python 3.13.5 and the native Ascon backend.
Setup observations identified liboqs 0.15.0 on the Pi. The Mac verifier used
Python 3.11.3, liboqs 0.16.0, liboqs-python 0.15.0, and PyCryptodome 3.23.0.
The original benchmark metadata did not pin every Pi package or native-library
revision, so those unrecorded versions must not be inferred.
