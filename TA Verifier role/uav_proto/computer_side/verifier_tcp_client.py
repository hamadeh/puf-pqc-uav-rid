#!/usr/bin/env python3
"""Live TCP client for the verifier-to-UAV authentication exchange."""

import argparse
import csv
import json
import socket
import statistics
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


REQUEST_HEADER = struct.Struct("!II")       # trial, request length
RESPONSE_HEADER = struct.Struct("!IIQ")     # trial, response length, Pi processing ns


def receive_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block:
            raise ConnectionError("TCP connection closed before all data arrived")
        data.extend(block)
    return bytes(data)


def archive_existing(path: Path) -> None:
    if not path.exists():
        return
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_name(f"{path.name}.backup_{stamp}")
    path.replace(backup)
    print(f"Archived existing response as: {backup}")


def run_exchange(host: str, port: int, trial: int, request: bytes,
                 timeout: float) -> tuple[bytes, float, float]:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        start_ns = time.perf_counter_ns()
        sock.sendall(REQUEST_HEADER.pack(trial, len(request)))
        sock.sendall(request)

        header = receive_exact(sock, RESPONSE_HEADER.size)
        returned_trial, response_size, pi_processing_ns = RESPONSE_HEADER.unpack(header)
        if returned_trial != trial:
            raise ValueError(
                f"response trial mismatch: sent {trial}, received {returned_trial}"
            )
        response = receive_exact(sock, response_size)
        rtt_ns = time.perf_counter_ns() - start_ns

    return response, rtt_ns / 1_000_000, pi_processing_ns / 1_000_000


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure the complete verifier/UAV exchange over TCP"
    )
    parser.add_argument("--host", required=True, help="Pi IPv4 address")
    parser.add_argument("--port", type=int, default=40444)
    parser.add_argument("--n", type=int, required=True)
    parser.add_argument("--trials", type=int, default=1,
                        help="number of recorded trials")
    parser.add_argument("--warmup", type=int, default=0,
                        help="unrecorded trials before measurement")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument(
        "--inter-trial-delay", type=float, default=0.0,
        help="seconds to wait between attempts (use at least 0.5 for the default UAV admission policy)",
    )
    parser.add_argument("--request", type=Path,
                        default=Path("out/verifier_reqauth.bin"))
    parser.add_argument("--response", type=Path,
                        default=Path("in/uav_response.bin"))
    parser.add_argument(
        "--fresh-request", action="store_true",
        help="generate a fresh nonce/KEM request before every exchange",
    )
    parser.add_argument(
        "--verify-response", action="store_true",
        help="cryptographically verify every received response after timing stops",
    )
    args = parser.parse_args()

    if args.trials < 1 or args.warmup < 0 or args.inter_trial_delay < 0:
        parser.error(
            "--trials must be at least 1; warmup and delay cannot be negative"
        )

    # With --fresh-request, the request file is intentionally allowed to be
    # absent at startup; verifier_phase4_request.py creates it per attempt.
    request = b"" if args.fresh_request else args.request.read_bytes()
    # Ensure a failed exchange cannot leave a stale response that a later
    # verifier invocation could accidentally process as if it were new.
    args.response.parent.mkdir(parents=True, exist_ok=True)
    archive_existing(args.response)
    rows = []
    last_response = None
    total_attempts = args.warmup + args.trials

    for attempt in range(total_attempts):
        if attempt and args.inter_trial_delay:
            time.sleep(args.inter_trial_delay)
        measured = attempt >= args.warmup
        trial = attempt - args.warmup + 1 if measured else 0
        try:
            if args.fresh_request:
                generated = subprocess.run(
                    [sys.executable, "verifier_phase4_request.py", "--force"],
                    text=True, capture_output=True,
                )
                if generated.returncode != 0:
                    raise RuntimeError(
                        "fresh request generation failed: "
                        + (generated.stderr or generated.stdout).strip()
                    )
                request = args.request.read_bytes()

            response, rtt_ms, pi_ms = run_exchange(
                args.host, args.port, trial, request, args.timeout
            )
            last_response = response
            args.response.write_bytes(response)

            verification = "not_run"
            if args.verify_response:
                checked = subprocess.run(
                    [sys.executable, "verifier_phase4_process_response.py"],
                    text=True, capture_output=True,
                )
                if checked.returncode != 0 or \
                   "ACCEPT: certificate, revocation, time, Merkle, and UAV signature checks passed." not in checked.stdout:
                    raise RuntimeError(
                        "response verification failed: "
                        + (checked.stderr or checked.stdout).strip()
                    )
                verification = "accepted"

            print(
                f"{'trial ' + str(trial) if measured else 'warmup'}: "
                f"RTT={rtt_ms:.3f} ms, Pi={pi_ms:.3f} ms, "
                f"request={len(request)} B, response={len(response)} B, "
                f"verification={verification}"
            )
            if measured:
                rows.append({
                    "trial": trial,
                    "status": "ok",
                    "verification": verification,
                    "rtt_ms": rtt_ms,
                    "pi_processing_ms": pi_ms,
                    "request_payload_bytes": len(request),
                    "response_payload_bytes": len(response),
                    "request_tcp_application_bytes": len(request) + REQUEST_HEADER.size,
                    "response_tcp_application_bytes": len(response) + RESPONSE_HEADER.size,
                    "error": "",
                })
        except Exception as exc:
            print(f"{'trial ' + str(trial) if measured else 'warmup'}: FAILED: {exc}")
            if measured:
                rows.append({
                    "trial": trial,
                    "status": "failed",
                    "verification": "failed" if args.verify_response else "not_run",
                    "rtt_ms": "",
                    "pi_processing_ms": "",
                    "request_payload_bytes": len(request),
                    "response_payload_bytes": "",
                    "request_tcp_application_bytes": len(request) + REQUEST_HEADER.size,
                    "response_tcp_application_bytes": "",
                    "error": str(exc),
                })

    successful = [row for row in rows if row["status"] == "ok"]
    if last_response is not None:
        args.response.write_bytes(last_response)
        print(f"Saved latest response: {args.response}")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = Path(f"live_unicast_n{args.n}_{stamp}.csv")
    json_path = Path(f"live_unicast_n{args.n}_{stamp}.json")
    fieldnames = [
        "trial", "status", "verification", "rtt_ms", "pi_processing_ms",
        "request_payload_bytes", "response_payload_bytes",
        "request_tcp_application_bytes", "response_tcp_application_bytes", "error",
    ]
    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    rtts = [float(row["rtt_ms"]) for row in successful]
    pi_times = [float(row["pi_processing_ms"]) for row in successful]
    summary = {
        "host": args.host,
        "port": args.port,
        "n": args.n,
        "warmup_trials": args.warmup,
        "recorded_trials": args.trials,
        "successful_trials": len(successful),
        "cryptographically_accepted_trials": sum(
            row["verification"] == "accepted" for row in rows
        ),
        "failed_trials": args.trials - len(successful),
        "application_failure_rate": (args.trials - len(successful)) / args.trials,
        "mean_rtt_ms": statistics.mean(rtts) if rtts else None,
        "std_rtt_ms": statistics.stdev(rtts) if len(rtts) > 1 else 0.0 if rtts else None,
        "mean_pi_processing_ms": statistics.mean(pi_times) if pi_times else None,
        "std_pi_processing_ms": (
            statistics.stdev(pi_times) if len(pi_times) > 1 else 0.0 if pi_times else None
        ),
        "note": (
            "Byte counts are TCP application bytes including this harness's framing; "
            "capture packets separately to report IP/TCP packet counts or link-layer loss."
        ),
    }
    json_path.write_text(json.dumps(summary, indent=2) + "\n")

    print(json.dumps(summary, indent=2))
    print(f"Wrote: {csv_path}")
    print(f"Wrote: {json_path}")

    if not successful:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
