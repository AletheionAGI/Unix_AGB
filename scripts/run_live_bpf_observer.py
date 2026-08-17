#!/usr/bin/env python3
"""Run bpftrace and stream normalized events without resetting sequences."""

from __future__ import annotations

import argparse
import json
import os
import selectors
import re
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from bpf_to_events import CorrelatingNormalizer


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=int, default=10)
    parser.add_argument("--broker-socket")
    parser.add_argument("--output-events", type=Path)
    parser.add_argument("--bpftrace-command", default="bpftrace")
    parser.add_argument("--target-uid", type=int, default=-1)
    parser.add_argument("--sensitive-path", action="append", default=[])
    parser.add_argument("--path-label", action="append", default=[], metavar="PATH=LABEL")
    args = parser.parse_args()
    if args.target_uid < -1:
        parser.error("--target-uid must be -1 (system-wide) or a non-negative UID")
    path_labels: dict[str, set[str]] = {}
    for mapping in args.path_label:
        path, separator, label = mapping.rpartition("=")
        if not separator or not path or not label:
            parser.error("--path-label must be PATH=LABEL")
        path_labels.setdefault(path, set()).add(label)
    bpftrace_uid = 4294967295 if args.target_uid == -1 else args.target_uid
    root = Path(__file__).resolve().parents[1]
    command = [
        *shlex.split(args.bpftrace_command),
        "-B",
        "line",
        str(root / "scripts/observe_live_bpf.bt"),
        str(bpftrace_uid),
        str(os.getpid()),
    ]
    if not command:
        parser.error("--bpftrace-command cannot be empty")
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
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
    normalizer = CorrelatingNormalizer()
    assert process.stdout
    assert process.stderr
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + args.duration
    lost_events = 0
    interrupted = False
    normalization_errors = 0
    try:
        while process.poll() is None and time.monotonic() < deadline:
            ready = selector.select(timeout=min(0.25, max(0, deadline - time.monotonic())))
            if not ready:
                continue
            key = ready[0][0]
            stream = key.fileobj
            line = stream.readline()
            if not line:
                selector.unregister(stream)
                if not selector.get_map():
                    break
                continue
            loss_match = re.search(r"(?:Lost|lost event count:)\s*(\d+)", line)
            if loss_match:
                lost_events = max(lost_events, int(loss_match.group(1)))
            if key.data == "stderr":
                print(line, end="", file=sys.stderr)
                continue
            try:
                event = normalizer.normalize(
                    line,
                    sequences,
                    sensitive_paths=set(args.sensitive_path),
                    path_labels=path_labels,
                )
            except (KeyError, OSError, ValueError) as error:
                normalization_errors += 1
                if normalization_errors <= 5:
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
    remaining_errors = process.stderr.read()
    if remaining_errors:
        print(remaining_errors, end="", file=sys.stderr)
        for match in re.finditer(r"(?:Lost|lost event count:)\s*(\d+)", remaining_errors):
            lost_events = max(lost_events, int(match.group(1)))
    if normalization_errors > 5:
        print(
            f"live_bpf_observer: suppressed {normalization_errors - 5} additional "
            "short-lived process normalization errors",
            file=sys.stderr,
        )
    status = (
        "stopped"
        if (return_code == 0 or timed_out or interrupted) and count and lost_events == 0
        else "failed"
    )
    if partial_path:
        if status == "stopped":
            partial_path.replace(args.output_events)
        else:
            partial_path.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "observer": "bpftrace",
                "events": count,
                "lost_events": lost_events,
                "status": status,
            }
        )
    )
    if status == "failed":
        if not count:
            print(
                "live_bpf_observer: no events captured; verify tracingfs/BPF privileges",
                file=sys.stderr,
            )
        if lost_events:
            print(
                "live_bpf_observer: capture rejected because kernel events were lost",
                file=sys.stderr,
            )
        raise SystemExit(return_code or 2)


if __name__ == "__main__":
    main()
