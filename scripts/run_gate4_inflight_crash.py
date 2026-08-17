#!/usr/bin/env python3
"""Recover one seccomp notification leased by a broker that dies before SEND."""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import select
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any

from benchmark_gate4_egress_broker import filtered_workload, latency_summary
from agb_fake_asm.enforcement_scope import process_tgid
from run_egress_seccomp_pilot import SECCOMP_IOCTL_NOTIF_SEND, SECCOMP_USER_NOTIF_FLAG_CONTINUE, notification_is_valid, receive_listener
from run_gate4_listener_guardian import start_broker


def respond_to_lease(listener: int, lease: dict[str, Any], target_pid: int) -> str:
    notification_id = int(lease["notification_id"])
    if not notification_is_valid(listener, notification_id):
        return "INVALID"
    try:
        deny = process_tgid(int(lease["notified_tid"])) == target_pid
    except (OSError, ValueError):
        return "UNRESOLVED"
    response = struct.pack("<Qqii", notification_id, 0, -errno.EACCES if deny else 0, 0 if deny else SECCOMP_USER_NOTIF_FLAG_CONTINUE)
    fcntl.ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response)
    return "DENY" if deny else "ALLOW"


def run_proof(*, attempts: int, threads: int, crash_after_received: int) -> dict[str, Any]:
    guardian_workload, workload_channel = socket.socketpair(type=socket.SOCK_SEQPACKET)
    workload_pid = os.fork()
    if workload_pid == 0:
        guardian_workload.close()
        os.setpgid(0, 0)
        filtered_workload(workload_channel, threads, attempts)
    workload_channel.close()
    listener = receive_listener(guardian_workload)
    executable = Path(sys.executable).resolve()
    generation = 1
    broker_pid, broker_channel = start_broker(
        listener,
        workload_pid,
        executable,
        generation,
        None,
        crash_before_send_after_received=crash_after_received,
        lease_reporting=True,
    )
    guardian_workload.send(b"GO")
    leases: dict[int, dict[str, Any]] = {}
    decisions: list[dict[str, Any]] = []
    crash_report: dict[str, Any] | None = None
    guardian_recovery_effect: str | None = None
    guardian_recovery_us: list[int] = []
    replacement_us: list[int] = []
    workload_status: dict[str, Any] | None = None
    invalid_ids = 0
    try:
        while True:
            target_denied = sum(item["target"] and item["effect"] == "DENY" for item in decisions) + (guardian_recovery_effect == "DENY")
            outsider_allowed = sum((not item["target"]) and item["effect"] == "ALLOW" for item in decisions) + (guardian_recovery_effect == "ALLOW")
            if workload_status is not None and target_denied == attempts and outsider_allowed >= 1:
                break
            ready, _, _ = select.select([guardian_workload, broker_channel], [], [], 2)
            if not ready:
                raise TimeoutError("in-flight recovery made no progress for two seconds")
            if guardian_workload in ready:
                payload = guardian_workload.recv(65536)
                if not payload:
                    raise RuntimeError("workload exited without status")
                workload_status = json.loads(payload)
            if broker_channel in ready:
                payload = broker_channel.recv(65536)
                if payload:
                    report = json.loads(payload)
                    if report["type"] == "lease":
                        leases[int(report["notification_id"])] = report
                    elif report["type"] == "decision":
                        decisions.append(report)
                        leases.clear()
                    elif report["type"] == "invalid":
                        invalid_ids += 1
                    elif report["type"] == "crash-before-send":
                        crash_report = report
                else:
                    recovery_started_ns = time.monotonic_ns()
                    _, status = os.waitpid(broker_pid, 0)
                    if os.waitstatus_to_exitcode(status) != 71 or generation != 1 or crash_report is None:
                        raise RuntimeError("unexpected in-flight broker exit")
                    lease = leases.get(int(crash_report["notification_id"]))
                    if lease is None:
                        raise RuntimeError("crashed broker had no guardian-visible lease")
                    guardian_recovery_effect = respond_to_lease(listener, lease, workload_pid)
                    guardian_recovery_us.append((time.monotonic_ns() - recovery_started_ns) // 1_000)
                    broker_channel.close()
                    replacement_started_ns = time.monotonic_ns()
                    generation += 1
                    broker_pid, broker_channel = start_broker(listener, workload_pid, executable, generation, None, lease_reporting=True)
                    replacement_us.append((time.monotonic_ns() - replacement_started_ns) // 1_000)
                    leases.clear()
    finally:
        try:
            os.kill(broker_pid, 9)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(broker_pid, 0)
        except ChildProcessError:
            pass
        broker_channel.close()
        os.close(listener)
        guardian_workload.close()
        try:
            os.killpg(workload_pid, 9)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(workload_pid, 0)
        except ChildProcessError:
            pass
    if workload_status is None:
        raise RuntimeError("missing workload status")
    target_denied = sum(item["target"] and item["effect"] == "DENY" for item in decisions) + (guardian_recovery_effect == "DENY")
    outsider_allowed = sum((not item["target"]) and item["effect"] == "ALLOW" for item in decisions) + (guardian_recovery_effect == "ALLOW")
    report = {
        "proof": "unix-agb-gate4-inflight-notification-recovery-v1",
        "policy_boundary": "guardian independently maps leased TID to the exact protected TGID; no sockaddr is disclosed",
        "configuration": {"attempts": attempts, "threads": threads, "crash_after_received": crash_after_received},
        "host": {"kernel": os.uname().release, "machine": os.uname().machine, "python": sys.version.split()[0]},
        "crash_report": crash_report,
        "guardian_recovery_effect": guardian_recovery_effect,
        "guardian_recovery_us": latency_summary(guardian_recovery_us),
        "replacement_ready_us": latency_summary(replacement_us),
        "decision_latency_us": latency_summary([item["latency_us"] for item in decisions]),
        "generations": generation,
        "decisions": {"broker_responses": len(decisions), "target_denied_total": target_denied, "outsider_allowed_total": outsider_allowed},
        "invalid_notification_ids": invalid_ids,
        "workload": workload_status,
        "criteria": {
            "crash_after_recv_before_send": crash_report is not None,
            "leased_notification_recovered": guardian_recovery_effect == "DENY",
            "replacement_generation_ready": generation == 2,
            "all_target_connects_denied": target_denied == attempts and int(workload_status["errno_counts"].get(str(errno.EACCES), 0)) == attempts,
            "out_of_scope_probe_allowed": outsider_allowed >= 1 and workload_status["outsider_exit_code"] == 0,
            "workload_completed_without_teardown": workload_status["attempts"] == attempts,
            "zero_invalid_notification_ids": invalid_ids == 0,
            "system_wide_changes": False,
        },
        "limitations": ["Recovery requires the broker to publish the notification lease before optional processing.", "The guardian remains a trusted single point of failure.", "The lease channel is process-private but not yet an authenticated persistent protocol."],
    }
    if not all(value for key, value in report["criteria"].items() if key != "system_wide_changes"):
        raise RuntimeError(f"in-flight recovery criteria failed: {report['criteria']}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts", type=int, default=256)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--crash-after-received", type=int, default=8)
    parser.add_argument("--output", type=Path, default=Path("var/benchmark/gate4-inflight-recovery.json"))
    args = parser.parse_args()
    report = run_proof(attempts=args.attempts, threads=args.threads, crash_after_received=args.crash_after_received)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
