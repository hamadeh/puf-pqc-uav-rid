"""Resident length-framed TCP server; activation occurs once at startup."""

import argparse
import os
import socket
import struct
import time

from uav_runtime import ProtocolAbort, UAVProtocolService

REQUEST_HEADER = struct.Struct("!II")
RESPONSE_HEADER = struct.Struct("!IIQ")
BASE = os.path.dirname(__file__)


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block:
            raise ConnectionError("connection closed during framed message")
        data.extend(block)
    return bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=40444)
    parser.add_argument("--n", type=int, required=True)
    args = parser.parse_args()
    service = UAVProtocolService(BASE)
    active_n = service.root["flight_ctx"]["n"]
    if active_n != args.n:
        raise SystemExit(f"active root has n={active_n}, not --n {args.n}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(5)
        print(f"Resident UAV TCP service on {args.host}:{args.port}, n={active_n}")
        while True:
            conn, address = server.accept()
            with conn:
                try:
                    trial, size = REQUEST_HEADER.unpack(
                        receive_exact(conn, REQUEST_HEADER.size)
                    )
                    if size > service.params["max_request_bytes"]:
                        raise ProtocolAbort("oversized request frame")
                    request = receive_exact(conn, size)
                    start = time.perf_counter_ns()
                    response = service.process_request(request)
                    processing = time.perf_counter_ns() - start
                    conn.sendall(
                        RESPONSE_HEADER.pack(trial, len(response), processing)
                    )
                    conn.sendall(response)
                    print(
                        f"Trial {trial} from {address[0]}: "
                        f"{size} B -> {len(response)} B, "
                        f"{processing / 1e6:.3f} ms"
                    )
                except (ValueError, ConnectionError, OSError) as exc:
                    print(f"Silent abort for {address[0]}: {exc}")


if __name__ == "__main__":
    main()
