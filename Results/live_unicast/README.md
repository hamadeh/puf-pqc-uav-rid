# Live Wi-Fi unicast authentication results

This directory contains the synchronized primary datasets for the live TCP
authentication exchange between the Raspberry Pi 5 UAV role and the Intel Mac
verifier role. One warmup was discarded and 30 fresh, cryptographically
verified sessions were recorded for each Merkle-root size.

| n | Application RTT (mean +/- sample SD) | Pi processing | TCP packets/exchange | Application payload | Accepted |
|---:|---:|---:|---:|---:|---:|
| 1024 | 420.734 +/- 90.835 ms | 336.430 +/- 13.818 ms | 61.833 +/- 2.306 | 52,523.7 B | 30/30 |
| 16384 | 1494.865 +/- 104.447 ms | 1387.340 +/- 13.125 ms | 63.667 +/- 3.155 | 53,431.8 B | 30/30 |

The client timer starts after TCP connection establishment, immediately before
the framed request is sent, and stops when the full framed response is
received. Request generation and final verifier processing are performed
outside this interval. Packet captures include the TCP handshake,
acknowledgements, retransmissions, and teardown.

No IPv4 fragmentation was observed. TShark marked 19 retransmissions for
`n=1024` and 17 for `n=16384`; TCP recovered them and all 60 measured exchanges
were accepted. These values do not represent IEEE 802.11 MAC retries or
isolated physical-layer loss.

The RTT includes Wi-Fi transport and UAV software processing. It must not be
reported as pure radio latency, physical PUF acquisition latency, or fabricated
silicon performance. LTspice PUF quantities elsewhere in the repository remain
simulation results.

Files:

- `live_unicast_n*_trials.csv`: raw per-trial application measurements.
- `live_unicast_n*_summary.json`: summaries emitted by the verifier client.
- `live_unicast_n*.pcap`: synchronized packet captures (one warmup plus 30
  measured TCP streams).
- `live_unicast_comparison.csv/.json`: manuscript-ready comparison and
  methodology boundaries.
- `live_unicast_table_rows.tex`: paste-ready LaTeX rows.
- `SHA256SUMS.txt`: integrity hashes for the six primary raw artifacts.

Reproduce the application experiment after completing enrollment and root
activation:

```bash
# Pi
python3 uav_tcp_server.py --n 1024

# Mac verifier
python3 verifier_tcp_client.py \
  --host PI_IP --port 40444 --n 1024 \
  --warmup 1 --trials 30 --fresh-request --verify-response
```

Repeat enrollment and the experiment with `--n 16384`. Capture TCP/IP traffic
separately with `tcpdump` if packet-level results are required.
