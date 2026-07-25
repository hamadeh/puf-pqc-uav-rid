"""Activate one TA-authorized root and emit 20-byte Profile-P UAS IDs."""

import argparse
import json
import os
import time

from uav_runtime import UAVProtocolService

BASE = os.path.dirname(__file__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    service = UAVProtocolService(BASE)
    log_path = os.path.join(BASE, "out", "broadcast_log.jsonl")
    for _ in range(args.count):
        record = service.broadcast_record()
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        print(f"UAS ID: {record['uas_id']} (20 bytes)")
        if args.count > 1:
            time.sleep(service.root["flight_ctx"]["delta_t"])
    print(f"Broadcast capture log: {log_path}")
    print("The public UAS ID carries no root or interval index.")


if __name__ == "__main__":
    main()
