#!/usr/bin/env python3
"""Normalize AGB_BPF lines into versioned SecurityEvent JSONL."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def subject_for(
    pid: int,
    *,
    uid: int | None = None,
    gid: int | None = None,
    fallback_exe: str | None = None,
) -> dict[str, object]:
    stat = Path(f"/proc/{pid}/stat").read_text().split()
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    status_fields = {}
    for line in status:
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            status_fields[parts[0].rstrip(":")] = parts[1].split()[0]
    ticks = int(stat[21])
    hz = os.sysconf("SC_CLK_TCK")
    try:
        executable = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        executable = fallback_exe or "<unavailable>"
    return {
        "pid": pid,
        "uid": uid if uid is not None else int(status_fields["Uid"]),
        "gid": gid if gid is not None else int(status_fields["Gid"]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "start_time_ns": ticks * 1_000_000_000 // hz,
        "exe": executable,
    }


def normalize(
    line: str,
    sequences: dict[str, int],
    *,
    sensitive_paths: set[str] | None = None,
) -> dict[str, object] | None:
    fields = line.rstrip("\n").split("|")
    if len(fields) < 3 or fields[0] != "AGB_BPF":
        return None
    operation = fields[1]
    attributes = dict(item.split("=", 1) for item in fields[2:] if "=" in item)
    pid = int(attributes["pid"])
    subject = subject_for(
        pid,
        uid=int(attributes["uid"]) if "uid" in attributes else None,
        gid=int(attributes["gid"]) if "gid" in attributes else None,
        fallback_exe=attributes.get("exe") or attributes.get("comm"),
    )
    namespace = f"process:{subject['boot_id']}:{pid}:{subject['start_time_ns']}"
    sequence = sequences.get(namespace, 0) + 1
    sequences[namespace] = sequence
    if operation == "process.exec":
        resource = {"type": "process", "path": attributes.get("exe", subject["exe"])}
        labels: list[str] = []
    elif operation == "file.open":
        path = attributes.get("path", "<unknown>")
        resource = {"type": "file", "path": path}
        labels = ["credential"] if path in (sensitive_paths or set()) else []
    elif operation == "network.connect":
        resource = {"type": "network", "fd": int(attributes.get("fd", "-1"))}
        family = attributes.get("family")
        if family:
            resource["family"] = family
        protocol_number = int(attributes.get("protocol", "0"))
        socket_type = int(attributes.get("socket_type", "0"))
        protocol_names = {6: "tcp", 17: "udp"}
        socket_type_names = {1: "stream", 2: "datagram", 3: "raw"}
        resource["protocol"] = protocol_names.get(protocol_number, "unknown")
        resource["protocol_number"] = protocol_number
        resource["socket_type"] = socket_type_names.get(socket_type & 0xF, "unknown")
        resource["socket_type_number"] = socket_type
        if "address" in attributes:
            resource["address"] = attributes["address"]
        if "port" in attributes:
            resource["port"] = int(attributes["port"])
        if "unix_path" in attributes:
            resource["path"] = attributes["unix_path"] or "<anonymous-unix-socket>"
        if "addrlen" in attributes:
            resource["addrlen"] = int(attributes["addrlen"])
        labels = ["network-destination-observed"] if family else []
    else:
        raise ValueError(f"unsupported BPF operation: {operation}")
    return {
        "schema_version": "1.0",
        "event_id": f"evt:bpf:{pid}:{sequence}:{time.monotonic_ns()}",
        "sequence": sequence,
        "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "monotonic_ns": time.monotonic_ns(),
        "host_id": f"host:{socket.gethostname().replace('.', '-')}",
        "namespace_id": namespace,
        "subject": subject,
        "operation": operation,
        "resource": resource,
        "result": "requested",
        "policy_revision": "policy:bpf-observer-v1",
        "labels": labels,
        "provenance": {"source": "bpf", "raw": line.rstrip("\n")},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="optional test PID for a single input stream")
    parser.add_argument("--output", help="write JSONL to a file instead of stdout")
    parser.add_argument("--sensitive-path", action="append", default=[])
    args = parser.parse_args()
    sequences: dict[str, int] = {}
    output = open(args.output, "w") if args.output else sys.stdout
    try:
        for line in sys.stdin:
            try:
                event = normalize(line, sequences, sensitive_paths=set(args.sensitive_path))
                if event is not None:
                    output.write(json.dumps(event, separators=(",", ":")) + "\n")
                    output.flush()
            except (KeyError, OSError, ValueError) as error:
                print(f"bpf_to_events: {error}", file=sys.stderr)
    finally:
        if args.output:
            output.close()


if __name__ == "__main__":
    main()
