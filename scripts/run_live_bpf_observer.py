#!/usr/bin/env python3
"""Run bpftrace and stream normalized events without resetting sequences."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from bpf_to_events import normalize


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--broker-socket")
    parser.add_argument("--output-events", type=Path)
    parser.add_argument("--bpftrace-command", default="bpftrace")
    parser.add_argument("--target-uid", type=int, default=-1)
    args = parser.parse_args()
    if args.target_uid < -1:
        parser.error("--target-uid must be -1 (system-wide) or a non-negative UID")
    bpftrace_uid = 4294967295 if args.target_uid == -1 else args.target_uid
    root = Path(__file__).resolve().parents[1]
    command = [
        *shlex.split(args.bpftrace_command),
        "-B",
        "line",
        str(root / "scripts/observe_live_bpf.bt"),
        str(bpftrace_uid),
    ]
    if not command:
        parser.error("--bpftrace-command cannot be empty")
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            process_group=0,
        )
    except FileNotFoundError:
        print('{"status":"unavailable","reason":"bpftrace-or-timeout-not-installed"}')
        raise SystemExit(2)

    output_file = None
    partial_path = None
    if args.output_events:
        args.output_events.parent.mkdir(parents=True, exist_ok=True)
        partial_path = args.output_events.with_suffix(args.output_events.suffix + ".partial")
        output_file = partial_path.open("w")
    count = 0
    sequences: dict[str, int] = {}
    assert process.stdout
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + args.duration
    interrupted = False
    try:
        while process.poll() is None and time.monotonic() < deadline:
            ready = selector.select(timeout=min(0.25, max(0, deadline - time.monotonic())))
            if not ready:
                continue
            line = process.stdout.readline()
            if not line:
                break
            try:
                event = normalize(line, sequences)
            except (KeyError, OSError, ValueError) as error:
                print(f"live_bpf_observer: {error}", file=sys.stderr)
                continue
            if event is None:
                continue
            if output_file:
                output_file.write(json.dumps(event, separators=(",", ":")) + "\n")
                output_file.flush()
            envelope: dict[str, object] = {"event": event}
            if args.broker_socket:
                resource = event.get("resource", {})
                assert isinstance(resource, dict)
                request = {
                    "namespace_id": event["namespace_id"],
                    "resource": resource.get("path") or str(resource.get("fd", "unknown")),
                    "policy_revision": event["policy_revision"],
                    "requested_effect": "ALLOW",
                    "operation": event["operation"],
                }
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.connect(args.broker_socket)
                    client.sendall((json.dumps(request) + "\n").encode())
                    response = client.makefile("rb").readline()
                envelope.update(broker_request=request, broker_response=json.loads(response))
            print(json.dumps(envelope))
            count += 1
    except KeyboardInterrupt:
        interrupted = True
    finally:
        selector.close()
        if output_file:
            output_file.close()
    timed_out = process.poll() is None
    if timed_out:
        os.killpg(process.pid, signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
    return_code = process.wait()
    status = "stopped" if (return_code == 0 or timed_out or interrupted) and count else "failed"
    if partial_path:
        if status == "stopped":
            partial_path.replace(args.output_events)
        else:
            partial_path.unlink(missing_ok=True)
    print(json.dumps({"observer": "bpftrace", "events": count, "status": status}))
    if status == "failed":
        if not count:
            print(
                "live_bpf_observer: no events captured; verify tracingfs/BPF privileges",
                file=sys.stderr,
            )
        raise SystemExit(return_code or 2)


if __name__ == "__main__":
    main()
