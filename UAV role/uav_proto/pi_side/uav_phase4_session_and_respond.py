"""One-shot file-channel wrapper around the resident UAV protocol service."""

import argparse
import os

from uav_runtime import UAVProtocolService

BASE = os.path.dirname(__file__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    request_path = os.path.join(BASE, "in", "verifier_reqauth.bin")
    response_path = os.path.join(BASE, "out", "uav_response.bin")
    if not os.path.exists(request_path):
        raise SystemExit(f"Missing {request_path}")
    if os.path.exists(response_path) and not args.force:
        raise SystemExit(f"Refusing to overwrite {response_path}; use --force.")
    service = UAVProtocolService(BASE)
    response = service.process_request(open(request_path, "rb").read())
    with open(response_path, "wb") as handle:
        handle.write(response)
    print(f"Wrote canonical binary UAV response: {response_path}")


if __name__ == "__main__":
    main()
