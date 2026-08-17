#!/usr/bin/env python3
"""Long-lived connect workload for the controlled Gate 3 policy transition."""

from __future__ import annotations

import argparse
import errno
import json
import os
import socket
import time
from pathlib import Path


def namespace_id() -> str:
    pid = os.getpid()
    ticks = int(Path(f"/proc/{pid}/stat").read_text().split()[21])
    start_ns = ticks * 1_000_000_000 // os.sysconf("SC_CLK_TCK")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return f"process:{boot}:{pid}:{start_ns}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", required=True)
    parser.add_argument("--port", type=int, default=9)
    parser.add_argument("--attempts", type=int, default=80)
    parser.add_argument("--delay-ms", type=int, default=100)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    results: list[str] = []
    namespace = namespace_id()
    for _ in range(args.attempts):
        channel = socket.socket()
        channel.settimeout(0.2)
        try:
            channel.connect((args.address, args.port))
            result = "CONNECTED"
        except OSError as error:
            result = errno.errorcode.get(error.errno, str(error.errno))
        finally:
            channel.close()
        results.append(result)
        temporary = args.state.with_suffix(".tmp")
        temporary.write_text(json.dumps({"namespace_id": namespace, "results": results}, sort_keys=True) + "\n")
        os.replace(temporary, args.state)
        time.sleep(args.delay_ms / 1000)


if __name__ == "__main__":
    main()
