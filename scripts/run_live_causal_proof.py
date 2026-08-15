#!/usr/bin/env python3
"""Run the controlled ptrace + Landlock Unix-AGB vertical slice."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WORKLOAD = ROOT / "target/debug/agb-lab-workload"
GATEWAY = ROOT / "target/debug/agb-gateway"


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def wait_for_trace(path: Path, needle: str, timeout: float = 3.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = path.read_text(errors="replace") if path.exists() else ""
        if needle in text:
            return text
        time.sleep(0.02)
    raise RuntimeError(f"trace did not contain {needle!r}")


def subject_for(pid: int, executable: Path) -> dict[str, Any]:
    stat = Path(f"/proc/{pid}/stat").read_text().split()
    ticks = int(stat[21])
    ticks_per_second = os.sysconf("SC_CLK_TCK")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return {
        "pid": pid,
        "uid": os.getuid(),
        "gid": os.getgid(),
        "boot_id": boot_id,
        "start_time_ns": ticks * 1_000_000_000 // ticks_per_second,
        "exe": str(executable),
    }


def make_event(
    case: str,
    sequence: int,
    subject: dict[str, Any],
    operation: str,
    resource: dict[str, Any],
    result: str,
    labels: list[str],
    source: str,
    trace_line: str | None = None,
) -> dict[str, Any]:
    namespace = (
        f"process:{subject['boot_id']}:{subject['pid']}:{subject['start_time_ns']}"
    )
    provenance: dict[str, Any] = {"source": source, "case": case}
    if trace_line is not None:
        provenance["trace_sha256"] = hashlib.sha256(trace_line.encode()).hexdigest()
    return {
        "schema_version": "1.0",
        "event_id": f"evt:live-{case}-{sequence}",
        "sequence": sequence,
        "occurred_at": now(),
        "monotonic_ns": time.monotonic_ns(),
        "host_id": f"host:{socket.gethostname().replace('.', '-')}",
        "namespace_id": namespace,
        "subject": subject,
        "operation": operation,
        "resource": resource,
        "result": result,
        "policy_revision": "policy:live-causal-proof-v1",
        "labels": labels,
        "provenance": provenance,
    }


def matching_line(trace: str, *needles: str) -> str:
    for line in trace.splitlines():
        if all(needle in line for needle in needles):
            return line
    raise RuntimeError(f"no trace line matches {needles!r}")


def gateway_event(gateway: subprocess.Popen[str], event: dict[str, Any]) -> dict[str, Any]:
    assert gateway.stdin is not None and gateway.stdout is not None
    gateway.stdin.write(json.dumps(event, separators=(",", ":")) + "\n")
    gateway.stdin.flush()
    response = gateway.stdout.readline()
    if not response:
        error = gateway.stderr.read() if gateway.stderr is not None else ""
        raise RuntimeError(f"gateway terminated: {error}")
    return json.loads(response)


def run_case(
    case: str,
    output: Path,
    secret: Path,
    config: Path,
    listener_port: int,
) -> dict[str, Any]:
    trace_path = output / f"{case}.strace"
    store_path = output / f"{case}.events.jsonl"
    # A rerun must be independent. These are generated laboratory artifacts,
    # never a canonical store or user data.
    trace_path.unlink(missing_ok=True)
    store_path.unlink(missing_ok=True)
    command = [
        "strace",
        "-f",
        "-qq",
        "-s",
        "4096",
        "-e",
        "trace=execve,connect,openat",
        "-o",
        str(trace_path),
        str(WORKLOAD),
        "--case",
        case,
        "--secret",
        str(secret),
        "--config",
        str(config),
        "--port",
        str(listener_port),
    ]
    worker = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    gateway = subprocess.Popen(
        [str(GATEWAY), "--store", str(store_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert worker.stdout is not None
        ready = json.loads(worker.stdout.readline())
        pid = int(ready["pid"])
        subject = subject_for(pid, WORKLOAD)

        trace = wait_for_trace(trace_path, str(WORKLOAD))
        exec_line = matching_line(trace, "execve(", str(WORKLOAD))
        events = [
            make_event(
                case,
                1,
                subject,
                "process.exec",
                {"type": "process", "path": str(WORKLOAD)},
                "allowed",
                [],
                "ptrace",
                exec_line,
            )
        ]

        if case == "benign":
            trace = wait_for_trace(trace_path, str(config))
            history_line = matching_line(trace, "openat(", str(config))
            events.append(
                make_event(
                    case,
                    2,
                    subject,
                    "file.open",
                    {"type": "file", "path": str(config)},
                    "allowed",
                    ["configuration"],
                    "ptrace",
                    history_line,
                )
            )
        else:
            trace = wait_for_trace(trace_path, "connect(")
            history_line = matching_line(trace, "connect(", f"htons({listener_port})")
            events.append(
                make_event(
                    case,
                    2,
                    subject,
                    "network.connect",
                    {"type": "network", "host": "127.0.0.1", "port": listener_port},
                    "allowed",
                    ["laboratory-loopback"],
                    "ptrace",
                    history_line,
                )
            )

        for event in events:
            gateway_event(gateway, event)
        request = make_event(
            case,
            3,
            subject,
            "file.open",
            {"type": "file", "path": str(secret)},
            "requested",
            ["credential"],
            "agent-broker",
        )
        decision_response = gateway_event(gateway, request)
        effect = decision_response["decision"]["effect"]

        assert worker.stdin is not None
        worker.stdin.write(effect + "\n")
        worker.stdin.flush()
        outcome = json.loads(worker.stdout.readline())
        return_code = worker.wait(timeout=5)
        if return_code != 0:
            error = worker.stderr.read() if worker.stderr is not None else ""
            raise RuntimeError(f"workload failed: {error}")

        trace = wait_for_trace(trace_path, str(secret))
        outcome_line = matching_line(trace, "openat(", str(secret))
        observed_result = "denied" if "EACCES" in outcome_line else "allowed"
        observed = make_event(
            case,
            4,
            subject,
            "file.open",
            {"type": "file", "path": str(secret)},
            observed_result,
            ["credential"],
            "ptrace",
            outcome_line,
        )
        gateway_event(gateway, observed)
        gateway.stdin.close()
        gateway_return_code = gateway.wait(timeout=5)
        if gateway_return_code != 0:
            error = gateway.stderr.read() if gateway.stderr is not None else ""
            raise RuntimeError(f"gateway failed: {error}")

        return {
            "case": case,
            "terminal_operation": request["operation"],
            "terminal_resource": request["resource"],
            "history_trace_sha256": events[-1]["provenance"]["trace_sha256"],
            "decision": decision_response["decision"],
            "gateway_enforcement": decision_response["enforcement"],
            "landlock_applied": effect == "DENY",
            "kernel_open_result": outcome["open_result"],
            "kernel_errno": outcome["errno"],
            "outcome_trace_sha256": observed["provenance"]["trace_sha256"],
        }
    finally:
        if worker.poll() is None:
            worker.kill()
        if gateway.poll() is None:
            gateway.kill()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="var/live-proof")
    args = parser.parse_args()
    if shutil.which("strace") is None:
        raise SystemExit("strace is required")
    if not WORKLOAD.exists() or not GATEWAY.exists():
        raise SystemExit("run `cargo build` first")

    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    secret = output / "api-token"
    config = output / "agent.conf"
    secret.write_text("laboratory-secret\n")
    config.write_text("mode=controlled\n")
    secret.chmod(0o600)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        benign = run_case("benign", output, secret, config, port)
        suspicious = run_case("suspicious", output, secret, config, port)
        connection, _ = listener.accept()
        connection.close()

    if benign["terminal_operation"] != suspicious["terminal_operation"]:
        raise SystemExit("terminal operations differ")
    if benign["terminal_resource"] != suspicious["terminal_resource"]:
        raise SystemExit("terminal resources differ")
    if benign["decision"]["effect"] != "ALLOW" or benign["kernel_open_result"] != "allowed":
        raise SystemExit("benign trajectory was not allowed")
    if suspicious["decision"]["effect"] != "DENY" or suspicious["kernel_open_result"] != "denied":
        raise SystemExit("suspicious trajectory was not denied")

    report = {
        "proof": "controlled-cooperative-ptrace-landlock-v1",
        "created_at": now(),
        "limitations": [
            "the authorization point is cooperative",
            "ptrace is a laboratory observer, not the planned production collector",
            "Landlock denial is installed inside the target process",
            "the deterministic fake state engine is not learned causal inference",
        ],
        "benign": benign,
        "suspicious": suspicious,
    }
    report_path = output / "REPORT.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print(f"report={report_path}")


if __name__ == "__main__":
    main()
