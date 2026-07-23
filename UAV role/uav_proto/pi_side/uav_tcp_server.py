#!/usr/bin/env python3
"""TCP transport wrapper for the UAV-side Algorithm 5+6 implementation."""

import argparse
import csv
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path


REQUEST_HEADER = struct.Struct("!II")       # trial, request length
RESPONSE_HEADER = struct.Struct("!IIQ")     # trial, response length, processing ns
MAX_REQUEST_BYTES = 4 * 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent
REQUEST_PATH = BASE_DIR / "in" / "verifier_reqauth.json"
RESPONSE_PATH = BASE_DIR / "out" / "uav_response.json"
UAV_HANDLER = BASE_DIR / "uav_phase4_session_and_respond.py"
LOG_PATH = BASE_DIR / "live_unicast_pi_processing.csv"


def receive_exact(connection: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        block = connection.recv(size - len(data))
        if not block:
            raise ConnectionError("peer closed the connection early")
        data.extend(block)
    return bytes(data)


def append_log(trial: int, peer: str, n: int, request_bytes: int,
               response_bytes: int, processing_ns: int) -> None:
    write_header = not LOG_PATH.exists()
    with LOG_PATH.open("a", newline="") as handle:
        writer = csv.writer(handle)
        if write_header:
            writer.writerow([
                "trial", "peer", "n", "request_bytes", "response_bytes",
                "processing_ms",
            ])
        writer.writerow([
            trial, peer, n, request_bytes, response_bytes,
            processing_ns / 1_000_000,
        ])


def handle_connection(connection: socket.socket, peer: tuple[str, int],
                      n: int) -> None:
    header = receive_exact(connection, REQUEST_HEADER.size)
    trial, request_size = REQUEST_HEADER.unpack(header)
    if request_size < 1 or request_size > MAX_REQUEST_BYTES:
        raise ValueError(f"invalid request length: {request_size}")

    request = receive_exact(connection, request_size)
    print(f"Trial {trial}: received {request_size} bytes from {peer[0]}", flush=True)

    REQUEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESPONSE_PATH.parent.mkdir(parents=True, exist_ok=True)
    REQUEST_PATH.write_bytes(request)

    # Never permit a failed handler invocation to reuse an earlier response.
    if RESPONSE_PATH.exists():
        RESPONSE_PATH.unlink()

    start_ns = time.perf_counter_ns()
    completed = subprocess.run(
        [sys.executable, str(UAV_HANDLER)],
        cwd=BASE_DIR,
        text=True,
        capture_output=True,
    )
    processing_ns = time.perf_counter_ns() - start_ns

    if completed.stdout:
        print(completed.stdout, end="", flush=True)
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr, flush=True)
    if completed.returncode != 0:
        raise RuntimeError(f"UAV handler exited with status {completed.returncode}")
    if not RESPONSE_PATH.exists():
        raise RuntimeError("UAV handler produced no response (protocol abort)")

    response = RESPONSE_PATH.read_bytes()
    connection.sendall(RESPONSE_HEADER.pack(trial, len(response), processing_ns))
    connection.sendall(response)
    append_log(trial, peer[0], n, request_size, len(response), processing_ns)
    print(
        f"Trial {trial}: sent {len(response)} bytes; "
        f"processing={processing_ns / 1_000_000:.3f} ms",
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="UAV live-unicast TCP server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=40444)
    parser.add_argument("--n", type=int, required=True,
                        help="experiment label; enrolled state must use the same n")
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.host, args.port))
        listener.listen(5)
        print(f"UAV TCP server waiting on {args.host}:{args.port}")
        print(f"Experiment n={args.n}")
        print("Press Ctrl+C to stop.")

        try:
            while True:
                connection, peer = listener.accept()
                with connection:
                    try:
                        handle_connection(connection, peer, args.n)
                    except Exception as exc:
                        print(f"Connection from {peer[0]} failed: {exc}", flush=True)
        except KeyboardInterrupt:
            print("\nServer stopped.")


if __name__ == "__main__":
    main()
