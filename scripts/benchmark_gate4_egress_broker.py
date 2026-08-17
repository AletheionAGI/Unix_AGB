#!/usr/bin/env python3
"""Concurrent, process-local seccomp user-notify egress benchmark."""

from __future__ import annotations

import argparse
import array
import concurrent.futures
import errno
import fcntl
import json
import math
import os
import select
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Any

from agb_fake_asm.egress_policy import ExecutableEgressPolicy
from agb_fake_asm.enforcement_scope import ArtifactIdentity, ExecutableProcessScope, ProcessIdentity, enforcement_effect, process_tgid
from agb_fake_asm.recovery_supervisor import RecoveringPolicyWorker
from run_egress_seccomp_pilot import (
    NOTIFICATION,
    SECCOMP_IOCTL_NOTIF_RECV,
    SECCOMP_IOCTL_NOTIF_SEND,
    SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    install_filter,
    notification_is_valid,
    read_sockaddr,
    receive_listener,
)

TEST_ADDRESS = "198.51.100.1"
TEST_PORT = 443


def percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def latency_summary(values: list[int]) -> dict[str, int]:
    return {
        "count": len(values),
        "min": min(values, default=0),
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values, default=0),
    }


def connect_once() -> int:
    candidate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        candidate.connect((TEST_ADDRESS, TEST_PORT))
        return 0
    except OSError as error:
        return error.errno or -1
    finally:
        candidate.close()


def filtered_workload(channel: socket.socket, workers: int, attempts: int) -> None:
    try:
        listener = install_filter()
        channel.sendmsg([b"ready"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [listener]))])
        if channel.recv(16) != b"GO":
            os._exit(126)

        outsider_pid = os.fork()
        if outsider_pid == 0:
            os.execv(sys.executable, [sys.executable, "-c", (
                "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                f"s.connect(('{TEST_ADDRESS}',{TEST_PORT})); s.close(); sys.exit(0)"
            )])
        results: list[int] = []
        lock = threading.Lock()

        def run(count: int) -> None:
            local = [connect_once() for _ in range(count)]
            with lock:
                results.extend(local)

        base, remainder = divmod(attempts, workers)
        threads = [
            threading.Thread(target=run, args=(base + (index < remainder),))
            for index in range(workers)
        ]
        started_ns = time.monotonic_ns()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        elapsed_ns = time.monotonic_ns() - started_ns
        _, outsider_status = os.waitpid(outsider_pid, 0)
        channel.send(json.dumps({
            "attempts": len(results),
            "errno_counts": {str(code): results.count(code) for code in sorted(set(results))},
            "elapsed_ns": elapsed_ns,
            "outsider_exit_code": os.waitstatus_to_exitcode(outsider_status),
        }).encode())
        os._exit(0)
    except BaseException as error:
        channel.send(json.dumps({"error": repr(error)}).encode())
        os._exit(125)


def evaluate_notification(
    notified_tid: int,
    args: tuple[int, ...],
    target_pid: int,
    scope: ExecutableProcessScope,
    policy: ExecutableEgressPolicy,
    delay_ms: float,
    fail_adapter: bool,
    recovery_worker: RecoveringPolicyWorker | None,
) -> dict[str, Any]:
    if delay_ms:
        time.sleep(delay_ms / 1000)
    notified_tgid = process_tgid(notified_tid)
    target = notified_tgid == target_pid
    adapter_failed = fail_adapter
    reason = "INJECTED_ADAPTER_FAILURE" if fail_adapter else "PID_OUT_OF_SCOPE"
    policy_effect = "ABSTAIN" if fail_adapter else "ALLOW"
    if not fail_adapter:
        resource = read_sockaddr(notified_tid, args[1], args[2])
        resource["type"] = "network"
        executable = os.readlink(f"/proc/{notified_tid}/exe")
        if target:
            valid, reason = scope.bind_or_verify(ProcessIdentity.from_pid(notified_tid, include_hash=False))
            adapter_failed = not valid
        decision = policy.evaluate({
            "operation": "network.connect",
            "result": "requested",
            "subject": {"exe": executable},
            "resource": resource,
        })
        policy_effect = decision["effect"]
        reason = decision["reason"] if not adapter_failed else reason
    worker_restarted = False
    worker_generation = None
    if recovery_worker is not None:
        supervised = recovery_worker.decide(policy_effect, target=target)
        policy_effect = supervised.effect
        reason = supervised.reason
        worker_restarted = supervised.worker_restarted
        worker_generation = supervised.generation
    return {
        "target": target,
        "adapter_failed": adapter_failed,
        "policy_effect": policy_effect,
        "reason": reason,
        "worker_restarted": worker_restarted,
        "worker_generation": worker_generation,
    }


def run_scenario(
    name: str,
    *,
    workers: int,
    attempts: int,
    broker_workers: int,
    queue_capacity: int,
    timeout_ms: float,
    delay_ms: float = 0,
    fail_adapter: bool = False,
    listener_loss: bool = False,
    recover_worker_crash: bool = False,
) -> dict[str, Any]:
    parent, child = socket.socketpair(type=socket.SOCK_SEQPACKET)
    pid = os.fork()
    if pid == 0:
        parent.close()
        os.setpgid(0, 0)
        filtered_workload(child, workers, attempts)
    child.close()
    listener = receive_listener(parent)
    expected = ArtifactIdentity.from_path(Path(sys.executable))
    scope = ExecutableProcessScope(pid, expected)
    pinned, pin_reason = scope.bind_or_verify(ProcessIdentity.from_pid(pid, include_hash=True))
    if not pinned:
        raise RuntimeError(f"could not pin benchmark target: {pin_reason}")
    policy = ExecutableEgressPolicy(expected.path)
    parent.send(b"GO")
    received = denied = allowed = overloaded = timed_out = invalid_ids = 0
    target_denied = outsider_allowed = 0
    latencies: list[int] = []
    pending: dict[concurrent.futures.Future[dict[str, Any]], tuple[int, int]] = {}
    started_ns = time.monotonic_ns()
    listener_loss_ns: int | None = None
    status_report: dict[str, Any] | None = None
    recovery_worker = RecoveringPolicyWorker(timeout_ms=50, crash_first_target=True) if recover_worker_crash else None
    worker_restarts = 0
    worker_generations: set[int] = set()

    def respond(notification_id: int, deny: bool) -> bool:
        nonlocal invalid_ids
        if not notification_is_valid(listener, notification_id):
            invalid_ids += 1
            return False
        response = struct.pack("<Qqii", notification_id, 0, -errno.EACCES if deny else 0, 0 if deny else SECCOMP_USER_NOTIF_FLAG_CONTINUE)
        fcntl.ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response)
        return True

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=broker_workers)
    try:
        while status_report is None:
            for future in list(pending):
                if not future.done():
                    continue
                notification_id, notification_started = pending.pop(future)
                elapsed_us = (time.monotonic_ns() - notification_started) // 1_000
                try:
                    result = future.result()
                except BaseException:
                    result = {"target": True, "adapter_failed": True, "policy_effect": "ABSTAIN", "reason": "ADAPTER_EXCEPTION"}
                timeout = elapsed_us > timeout_ms * 1000
                effect = enforcement_effect(result["policy_effect"], target_pid=result["target"], adapter_failed=result["adapter_failed"], timed_out=timeout)
                if respond(notification_id, effect == "DENY"):
                    latencies.append(elapsed_us)
                    denied += effect == "DENY"
                    allowed += effect == "ALLOW"
                    timed_out += timeout and result["target"] and effect == "DENY"
                    target_denied += result["target"] and effect == "DENY"
                    outsider_allowed += (not result["target"]) and effect == "ALLOW"
                    worker_restarts += result.get("worker_restarted", False)
                    if result.get("worker_generation") is not None:
                        worker_generations.add(result["worker_generation"])

            watched = [parent] if listener < 0 else [parent, listener]
            ready, _, _ = select.select(watched, [], [], 0.001)
            if listener_loss_ns is not None and time.monotonic_ns() - listener_loss_ns > 2_000_000_000:
                os.killpg(pid, 9)
                status_report = {
                    "attempts": 0,
                    "planned_attempts": attempts,
                    "errno_counts": {},
                    "elapsed_ns": time.monotonic_ns() - listener_loss_ns,
                    "outsider_exit_code": None,
                    "watchdog_terminated": True,
                }
                continue
            if parent in ready:
                payload = parent.recv(65536)
                if not payload:
                    raise RuntimeError("benchmark child exited without status")
                status_report = json.loads(payload)
                continue
            if listener < 0 or listener not in ready:
                continue
            notification = bytearray(NOTIFICATION.size)
            try:
                fcntl.ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, notification, True)
            except OSError as error:
                if error.errno in {errno.ENOENT, errno.EINTR}:
                    continue
                raise
            values = NOTIFICATION.unpack(notification)
            notification_id, notified_tid = values[0], values[1]
            args = tuple(values[6:])
            received += 1
            if listener_loss:
                os.close(listener)
                listener = -1
                listener_loss_ns = time.monotonic_ns()
                listener_loss = False
                continue
            notification_started = time.monotonic_ns()
            try:
                target = process_tgid(notified_tid) == pid
            except (OSError, ValueError):
                target = True
            if len(pending) >= queue_capacity:
                effect = enforcement_effect("ALLOW", target_pid=target, adapter_failed=False, overloaded=True)
                if respond(notification_id, effect == "DENY"):
                    elapsed_us = (time.monotonic_ns() - notification_started) // 1_000
                    latencies.append(elapsed_us)
                    overloaded += 1
                    denied += effect == "DENY"
                    allowed += effect == "ALLOW"
                    target_denied += target and effect == "DENY"
                    outsider_allowed += (not target) and effect == "ALLOW"
                continue
            future = executor.submit(evaluate_notification, notified_tid, args, pid, scope, policy, delay_ms, fail_adapter, recovery_worker)
            pending[future] = (notification_id, notification_started)
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        if recovery_worker is not None:
            recovery_worker.close()
        if listener >= 0:
            os.close(listener)
        parent.close()
        try:
            os.killpg(pid, 9)
        except ProcessLookupError:
            pass
        try:
            _, child_status = os.waitpid(pid, 0)
        except ChildProcessError:
            child_status = 0
    wall_ns = time.monotonic_ns() - started_ns
    if status_report is None or "error" in status_report:
        raise RuntimeError(f"invalid workload status: {status_report}")
    completed = int(status_report["attempts"])
    return {
        "name": name,
        "configuration": {"workload_threads": workers, "attempts": attempts, "broker_workers": broker_workers, "queue_capacity": queue_capacity, "timeout_ms": timeout_ms, "injected_delay_ms": delay_ms, "injected_adapter_failure": fail_adapter, "injected_policy_worker_crash": recover_worker_crash},
        "notifications_received": received,
        "responses": {"deny": denied, "allow": allowed, "target_denied": target_denied, "outsider_allowed": outsider_allowed, "overload_fail_closed": overloaded, "timeout_fail_closed": timed_out, "policy_worker_restarts": worker_restarts, "policy_worker_generations": sorted(worker_generations)},
        "workload": status_report,
        "latency_us": latency_summary(latencies),
        "throughput_responses_per_second": round((denied + allowed) / (wall_ns / 1e9), 2),
        "invalid_notification_ids": invalid_ids,
        "listener_lost": listener < 0,
        "system_wide_changes": False,
        "completed": completed == attempts,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts", type=int, default=256)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--output", type=Path, default=Path("var/benchmark/gate4-egress-broker-benchmark.json"))
    args = parser.parse_args()
    if args.attempts < 16 or args.threads < 2:
        parser.error("benchmark requires at least 16 attempts and 2 threads")
    scenarios = [
        run_scenario("normal", workers=args.threads, attempts=args.attempts, broker_workers=4, queue_capacity=64, timeout_ms=100),
        run_scenario("bounded-overload", workers=args.threads * 2, attempts=args.attempts, broker_workers=1, queue_capacity=2, timeout_ms=100, delay_ms=5),
        run_scenario("decision-timeout", workers=args.threads, attempts=max(16, args.attempts // 4), broker_workers=2, queue_capacity=64, timeout_ms=1, delay_ms=5),
        run_scenario("adapter-failure", workers=args.threads, attempts=max(16, args.attempts // 4), broker_workers=2, queue_capacity=64, timeout_ms=100, fail_adapter=True),
        run_scenario("worker-crash-recovery", workers=args.threads, attempts=max(16, args.attempts // 4), broker_workers=2, queue_capacity=64, timeout_ms=100, recover_worker_crash=True),
        run_scenario("listener-loss", workers=args.threads, attempts=max(16, args.attempts // 4), broker_workers=2, queue_capacity=64, timeout_ms=100, listener_loss=True),
    ]
    for scenario in scenarios[:5]:
        if not scenario["completed"] or scenario["workload"]["outsider_exit_code"] != 0:
            raise RuntimeError(f"live-listener scenario failed isolation/completion: {scenario['name']}")
        errno_counts = scenario["workload"]["errno_counts"]
        if int(errno_counts.get(str(errno.EACCES), 0)) != scenario["configuration"]["attempts"]:
            raise RuntimeError(f"target was not fully fail-closed: {scenario['name']}")
        if scenario["invalid_notification_ids"]:
            raise RuntimeError(f"invalid notification IDs: {scenario['name']}")
    report = {
        "proof": "unix-agb-gate4-supervised-seccomp-broker-v2",
        "measurement_boundary": "connect syscall notification received by userspace through seccomp response submission",
        "host": {"kernel": os.uname().release, "machine": os.uname().machine, "python": sys.version.split()[0]},
        "scenarios": scenarios,
        "criteria": {
            "live_listener_target_connects_denied": all(s["responses"]["target_denied"] == s["configuration"]["attempts"] for s in scenarios[:5]),
            "live_listener_outsider_connects_allowed": all(s["responses"]["outsider_allowed"] >= 1 and s["workload"]["outsider_exit_code"] == 0 for s in scenarios[:5]),
            "overload_exercised": scenarios[1]["responses"]["overload_fail_closed"] > 0,
            "timeouts_exercised": scenarios[2]["responses"]["timeout_fail_closed"] > 0,
            "adapter_failure_exercised": scenarios[3]["configuration"]["injected_adapter_failure"],
            "worker_crash_recovered": scenarios[4]["responses"]["policy_worker_restarts"] == 1 and len(scenarios[4]["responses"]["policy_worker_generations"]) >= 1,
            "zero_invalid_notification_ids": all(s["invalid_notification_ids"] == 0 for s in scenarios[:5]),
            "listener_loss_stalls_until_watchdog": scenarios[5]["workload"].get("watchdog_terminated", False) and scenarios[5]["workload"]["attempts"] == 0,
            "listener_loss_preserves_inherited_outsider": scenarios[5]["workload"]["outsider_exit_code"] == 0,
            "system_wide_changes": False,
        },
        "limitations": [
            "Disposable process-local seccomp filters only; no persistent broker was installed.",
            "Throughput is host- and workload-specific and is not a production capacity claim.",
            "Closing the listener models total broker loss. On this host, notified calls stalled until the two-second watchdog terminated the disposable process group; the inherited out-of-scope subprocess was also disrupted. This is a promotion blocker.",
        ],
    }
    required = {key: value for key, value in report["criteria"].items() if key not in {"system_wide_changes", "listener_loss_preserves_inherited_outsider"}}
    if not all(required.values()):
        raise RuntimeError("one or more benchmark criteria failed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
