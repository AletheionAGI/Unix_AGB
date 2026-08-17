#!/usr/bin/env python3
"""Retained-listener guardian and broker-generation handoff proof."""

from __future__ import annotations

import argparse
import array
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

from agb_fake_asm.enforcement_scope import ArtifactIdentity, ExecutableProcessScope, ProcessIdentity, enforcement_effect, process_tgid
from benchmark_gate4_egress_broker import filtered_workload, latency_summary
from run_egress_seccomp_pilot import NOTIFICATION, SECCOMP_IOCTL_NOTIF_RECV, SECCOMP_IOCTL_NOTIF_SEND, SECCOMP_USER_NOTIF_FLAG_CONTINUE, notification_is_valid, receive_listener


def receive_handoff(channel: socket.socket) -> int:
    message, ancillary, *_ = channel.recvmsg(64, socket.CMSG_LEN(array.array("i").itemsize))
    if message != b"listener":
        raise RuntimeError("invalid listener handoff")
    descriptors = array.array("i")
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors.frombytes(data[: descriptors.itemsize])
    if len(descriptors) != 1:
        raise RuntimeError("listener handoff must contain exactly one descriptor")
    return descriptors[0]


def broker_main(channel: socket.socket) -> None:
    config = json.loads(channel.recv(4096))
    listener = receive_handoff(channel)
    target_pid = int(config["target_pid"])
    expected = ArtifactIdentity.from_path(Path(config["executable"]))
    scope = ExecutableProcessScope(target_pid, expected)
    valid, reason = scope.bind_or_verify(ProcessIdentity.from_pid(target_pid, include_hash=True))
    if not valid:
        channel.send(json.dumps({"type": "fatal", "reason": reason}).encode())
        os._exit(125)
    generation = int(config["generation"])
    crash_after = config.get("crash_after")
    processed = 0
    channel.send(json.dumps({"type": "ready", "generation": generation}).encode())
    while True:
        notification = bytearray(NOTIFICATION.size)
        try:
            fcntl.ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, notification, True)
        except OSError as error:
            if error.errno in {errno.EINTR, errno.ENOENT}:
                continue
            raise
        values = NOTIFICATION.unpack(notification)
        notification_id, notified_tid = values[0], values[1]
        started_ns = time.monotonic_ns()
        if not notification_is_valid(listener, notification_id):
            channel.send(json.dumps({"type": "invalid", "generation": generation}).encode())
            continue
        try:
            notified_tgid = process_tgid(notified_tid)
            target = notified_tgid == target_pid
            adapter_failed = False
            if target:
                identity_ok, identity_reason = scope.bind_or_verify(ProcessIdentity.from_pid(notified_tid, include_hash=False))
                adapter_failed = not identity_ok
            policy_effect = "DENY" if target else "ALLOW"
            effect = enforcement_effect(policy_effect, target_pid=target, adapter_failed=adapter_failed)
        except (OSError, ValueError):
            target = True
            effect = enforcement_effect("ABSTAIN", target_pid=True, adapter_failed=True)
        if not notification_is_valid(listener, notification_id):
            channel.send(json.dumps({"type": "invalid", "generation": generation}).encode())
            continue
        deny = effect == "DENY"
        response = struct.pack("<Qqii", notification_id, 0, -errno.EACCES if deny else 0, 0 if deny else SECCOMP_USER_NOTIF_FLAG_CONTINUE)
        fcntl.ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response)
        processed += 1
        channel.send(json.dumps({
            "type": "decision",
            "generation": generation,
            "target": target,
            "effect": effect,
            "latency_us": (time.monotonic_ns() - started_ns) // 1_000,
        }).encode())
        if crash_after is not None and processed >= int(crash_after):
            channel.send(json.dumps({"type": "crash", "generation": generation, "after_responses": processed}).encode())
            os._exit(70)


def start_broker(listener: int, target_pid: int, executable: Path, generation: int, crash_after: int | None) -> tuple[int, socket.socket]:
    guardian, broker = socket.socketpair(type=socket.SOCK_SEQPACKET)
    pid = os.fork()
    if pid == 0:
        guardian.close()
        os.close(listener)
        try:
            broker_main(broker)
        finally:
            os._exit(125)
    broker.close()
    guardian.send(json.dumps({"target_pid": target_pid, "executable": str(executable), "generation": generation, "crash_after": crash_after}).encode())
    guardian.sendmsg([b"listener"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [listener]))])
    ready = json.loads(guardian.recv(4096))
    if ready.get("type") != "ready" or ready.get("generation") != generation:
        raise RuntimeError(f"broker generation failed to start: {ready}")
    return pid, guardian


def run_proof(*, attempts: int, threads: int, crash_after: int) -> dict[str, Any]:
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
    broker_pid, broker_channel = start_broker(listener, workload_pid, executable, generation, crash_after)
    guardian_workload.send(b"GO")
    decisions: list[dict[str, Any]] = []
    invalid_ids = 0
    recovery_us: list[int] = []
    crash_reports: list[dict[str, Any]] = []
    workload_status: dict[str, Any] | None = None
    try:
        while True:
            target_denied = sum(item["target"] and item["effect"] == "DENY" for item in decisions)
            outsider_allowed = sum((not item["target"]) and item["effect"] == "ALLOW" for item in decisions)
            if workload_status is not None and target_denied == attempts and outsider_allowed >= 1:
                break
            ready, _, _ = select.select([guardian_workload, broker_channel], [], [], 2)
            if not ready:
                raise TimeoutError("guardian made no progress for two seconds")
            if guardian_workload in ready:
                payload = guardian_workload.recv(65536)
                if not payload:
                    raise RuntimeError("workload exited without status")
                workload_status = json.loads(payload)
            if broker_channel in ready:
                payload = broker_channel.recv(65536)
                if payload:
                    report = json.loads(payload)
                    if report["type"] == "decision":
                        decisions.append(report)
                    elif report["type"] == "invalid":
                        invalid_ids += 1
                    elif report["type"] == "crash":
                        crash_reports.append(report)
                else:
                    replacement_started_ns = time.monotonic_ns()
                    _, status = os.waitpid(broker_pid, 0)
                    if os.waitstatus_to_exitcode(status) != 70 or generation != 1:
                        raise RuntimeError("unexpected broker exit")
                    broker_channel.close()
                    generation += 1
                    broker_pid, broker_channel = start_broker(listener, workload_pid, executable, generation, None)
                    recovery_us.append((time.monotonic_ns() - replacement_started_ns) // 1_000)
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
    target_denied = sum(item["target"] and item["effect"] == "DENY" for item in decisions)
    outsider_allowed = sum((not item["target"]) and item["effect"] == "ALLOW" for item in decisions)
    report = {
        "proof": "unix-agb-gate4-retained-listener-guardian-v1",
        "policy_boundary": "predeclared exact-target external-network denial; sockaddr decoding is not performed by the sibling broker",
        "configuration": {"attempts": attempts, "threads": threads, "first_generation_crash_after_responses": crash_after},
        "host": {"kernel": os.uname().release, "machine": os.uname().machine, "python": sys.version.split()[0]},
        "generations": generation,
        "crash_reports": crash_reports,
        "recovery_us": latency_summary(recovery_us),
        "decision_latency_us": latency_summary([item["latency_us"] for item in decisions]),
        "decisions": {"total": len(decisions), "target_denied": target_denied, "outsider_allowed": outsider_allowed},
        "invalid_notification_ids": invalid_ids,
        "workload": workload_status,
        "criteria": {
            "broker_crash_injected": len(crash_reports) == 1,
            "replacement_generation_ready": generation == 2,
            "all_target_connects_denied": target_denied == attempts and int(workload_status["errno_counts"].get(str(errno.EACCES), 0)) == attempts,
            "out_of_scope_probe_allowed": outsider_allowed >= 1 and workload_status["outsider_exit_code"] == 0,
            "zero_invalid_notification_ids": invalid_ids == 0,
            "workload_completed": workload_status["attempts"] == attempts,
            "system_wide_changes": False,
        },
        "rollback": "disposable protected process group exited; guardian closed its retained listener",
        "limitations": ["The guardian remains a trusted single point of failure.", "The handoff is local and process-private, not yet authenticated as a persistent service protocol."],
    }
    if not all(value for key, value in report["criteria"].items() if key != "system_wide_changes"):
        raise RuntimeError(f"guardian criteria failed: {report['criteria']}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts", type=int, default=256)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--crash-after", type=int, default=8)
    parser.add_argument("--output", type=Path, default=Path("var/benchmark/gate4-listener-guardian.json"))
    args = parser.parse_args()
    if not 1 <= args.crash_after < args.attempts:
        parser.error("crash-after must be within the workload")
    report = run_proof(attempts=args.attempts, threads=args.threads, crash_after=args.crash_after)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
