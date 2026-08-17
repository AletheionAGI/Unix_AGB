#!/usr/bin/env python3
"""Disposable process tree used only by the transient-cgroup proof."""

import argparse
import json
import os
import time
from pathlib import Path


def cgroup(pid: int) -> str:
    line = Path(f"/proc/{pid}/cgroup").read_text().strip()
    return line.split("::", 1)[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--guardian-delay-ms", type=int, default=100)
    args = parser.parse_args()
    guardian = os.fork()
    if guardian == 0:
        time.sleep(args.guardian_delay_ms / 1000)
        os._exit(73)
    broker = os.fork()
    if broker == 0:
        time.sleep(30)
        os._exit(0)
    report = {
        "launcher_pid": os.getpid(),
        "guardian_pid": guardian,
        "broker_pid": broker,
        "cgroups": {
            "launcher": cgroup(os.getpid()),
            "guardian": cgroup(guardian),
            "broker": cgroup(broker),
        },
    }
    args.state.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.state.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    temporary.replace(args.state)
    os.waitpid(guardian, 0)
    time.sleep(30)


if __name__ == "__main__":
    main()
