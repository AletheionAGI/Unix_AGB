#!/usr/bin/env python3
"""Normalize AGB_BPF lines into versioned SecurityEvent JSONL."""

from __future__ import annotations

import argparse
import errno
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def decode_sockaddr(encoded: str) -> dict[str, object]:
    raw = bytes.fromhex(encoded.replace("\\x", "").replace(" ", ""))
    if len(raw) < 2:
        raise ValueError("sockaddr snapshot is truncated")
    family = int.from_bytes(raw[:2], sys.byteorder)
    if family == socket.AF_INET and len(raw) >= 8:
        return {
            "family": "AF_INET",
            "port": int.from_bytes(raw[2:4], "big"),
            "address": socket.inet_ntop(socket.AF_INET, raw[4:8]),
        }
    if family == socket.AF_INET6 and len(raw) >= 24:
        return {
            "family": "AF_INET6",
            "port": int.from_bytes(raw[2:4], "big"),
            "address": socket.inet_ntop(socket.AF_INET6, raw[8:24]),
        }
    if family == socket.AF_UNIX:
        path = raw[2:].split(b"\0", 1)[0].decode(errors="replace")
        return {"family": "AF_UNIX", "unix_path": path}
    return {"family": str(family)}


def parse_bpf_line(line: str) -> tuple[str, dict[str, str]] | None:
    fields = line.rstrip("\n").split("|")
    if len(fields) < 3 or fields[0] != "AGB_BPF":
        return None
    return fields[1], dict(item.split("=", 1) for item in fields[2:] if "=" in item)


class CorrelatingNormalizer:
    """Join syscall entry metadata to its exit before emitting evidence."""

    def __init__(self) -> None:
        self.pending: dict[tuple[str, str], dict[str, str]] = {}

    def normalize(self, line: str, sequences: dict[str, int], **kwargs: Any) -> dict[str, object] | None:
        parsed = parse_bpf_line(line)
        if parsed is None:
            return None
        operation, attributes = parsed
        if operation.endswith(".enter"):
            base = operation.removesuffix(".enter")
            self.pending[(attributes["tid"], base)] = attributes
            return None
        if operation.endswith(".sockaddr"):
            base = operation.removesuffix(".sockaddr")
            pending = self.pending.get((attributes["tid"], base))
            if pending is not None:
                pending.update(attributes)
            return None
        if operation.endswith(".exit"):
            base = operation.removesuffix(".exit")
            entered = self.pending.pop((attributes["tid"], base), None)
            if entered is None:
                return None
            merged = {**entered, **attributes}
            encoded = "|".join(
                ["AGB_BPF", base, *(f"{key}={value}" for key, value in merged.items())]
            )
            return normalize(encoded, sequences, **kwargs)
        return normalize(line, sequences, **kwargs)


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
    try:
        cmdline = [
            part.decode(errors="replace")
            for part in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if part
        ]
    except OSError:
        cmdline = []
    return {
        "pid": pid,
        "ppid": int(stat[3]),
        "uid": uid if uid is not None else int(status_fields["Uid"]),
        "gid": gid if gid is not None else int(status_fields["Gid"]),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "start_time_ns": ticks * 1_000_000_000 // hz,
        "exe": executable,
        "cmdline": cmdline,
    }


def normalize(
    line: str,
    sequences: dict[str, int],
    *,
    sensitive_paths: set[str] | None = None,
    path_labels: dict[str, set[str]] | None = None,
) -> dict[str, object] | None:
    parsed = parse_bpf_line(line)
    if parsed is None:
        return None
    operation, attributes = parsed
    if "sockaddr_hex" in attributes:
        attributes.update(
            {key: str(value) for key, value in decode_sockaddr(attributes["sockaddr_hex"]).items()}
        )
    pid = int(attributes["pid"])
    subject = subject_for(
        pid,
        uid=int(attributes["uid"]) if "uid" in attributes else None,
        gid=int(attributes["gid"]) if "gid" in attributes else None,
        fallback_exe=attributes.get("exe") or attributes.get("comm"),
    )
    # sched_process_exec fires while /proc/<pid>/exe may still expose a
    # transient identity.  The tracepoint filename is the executable that was
    # actually selected by exec and is authoritative for this event.
    if operation == "process.exec" and attributes.get("exe"):
        subject["exe"] = attributes["exe"]
    namespace = f"process:{subject['boot_id']}:{pid}:{subject['start_time_ns']}"
    sequence = sequences.get(namespace, 0) + 1
    sequences[namespace] = sequence
    if operation == "process.exec":
        resource = {"type": "process", "path": attributes.get("exe", subject["exe"])}
        labels: list[str] = []
    elif operation == "file.open":
        path = attributes.get("path", "<unknown>")
        resource = {"type": "file", "path": path}
        if "flags" in attributes:
            flags = int(attributes["flags"])
            access_modes = {
                os.O_RDONLY: "read",
                os.O_WRONLY: "write",
                os.O_RDWR: "read-write",
            }
            resource["open_flags"] = flags
            resource["access"] = access_modes.get(flags & os.O_ACCMODE, "unknown")
        observed_labels = set((path_labels or {}).get(path, set()))
        if path in (sensitive_paths or set()):
            observed_labels.add("credential")
        labels = sorted(observed_labels)
    elif operation in {"network.socket", "network.bind", "network.connect"}:
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
        labels = (
            ["network-destination-observed"]
            if family and operation in {"network.bind", "network.connect"}
            else []
        )
    else:
        raise ValueError(f"unsupported BPF operation: {operation}")
    result = "requested"
    if "ret" in attributes:
        return_value = int(attributes["ret"])
        resource["return_value"] = return_value
        if return_value >= 0:
            result = "allowed"
        else:
            error_number = -return_value
            resource["error_number"] = error_number
            resource["error_name"] = errno.errorcode.get(error_number, "UNKNOWN")
            if operation == "network.connect" and error_number in {
                errno.EINPROGRESS,
                errno.EALREADY,
            }:
                result = "pending"
            else:
                result = "denied" if error_number in {errno.EACCES, errno.EPERM} else "failed"
    if "syscall" in attributes:
        resource["syscall"] = attributes["syscall"]
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
        "result": result,
        "policy_revision": (
            "policy:bpf-observer-v2"
            if "ret" in attributes or attributes.get("observer") == "v2"
            else "policy:bpf-observer-v1"
        ),
        "labels": labels,
        "provenance": {"source": "bpf", "raw": line.rstrip("\n")},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, help="optional test PID for a single input stream")
    parser.add_argument("--output", help="write JSONL to a file instead of stdout")
    parser.add_argument("--sensitive-path", action="append", default=[])
    parser.add_argument("--path-label", action="append", default=[], metavar="PATH=LABEL")
    args = parser.parse_args()
    path_labels: dict[str, set[str]] = {}
    for mapping in args.path_label:
        path, separator, label = mapping.rpartition("=")
        if not separator or not path or not label:
            parser.error("--path-label must be PATH=LABEL")
        path_labels.setdefault(path, set()).add(label)
    sequences: dict[str, int] = {}
    output = open(args.output, "w") if args.output else sys.stdout
    try:
        for line in sys.stdin:
            try:
                event = normalize(
                    line,
                    sequences,
                    sensitive_paths=set(args.sensitive_path),
                    path_labels=path_labels,
                )
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
