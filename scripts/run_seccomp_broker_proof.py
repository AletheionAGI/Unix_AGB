#!/usr/bin/env python3
"""External seccomp-user-notify proof for a disposable secret file."""

from __future__ import annotations

import array
import ctypes
import errno
import fcntl
import json
import os
import socket
import struct
import subprocess
import tempfile
import time
import select
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from agb_fake_asm import DecisionCache

LIB = ctypes.CDLL("libseccomp.so.2", use_errno=True)
LIBC = ctypes.CDLL(None, use_errno=True)
SCMP_ACT_NOTIFY = 0x7FC00000
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_SYS_OPENAT = 257
SECCOMP_IOCTL_NOTIF_RECV = 0xC0502100
SECCOMP_IOCTL_NOTIF_SEND = 0xC0182101
SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1
BROKER_TIMEOUT_S = 2.0

LIB.seccomp_init.argtypes = [ctypes.c_uint32]
LIB.seccomp_init.restype = ctypes.c_void_p
LIB.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
LIB.seccomp_rule_add.restype = ctypes.c_int
LIB.seccomp_load.argtypes = [ctypes.c_void_p]
LIB.seccomp_load.restype = ctypes.c_int
LIB.seccomp_notify_fd.argtypes = [ctypes.c_void_p]
LIB.seccomp_notify_fd.restype = ctypes.c_int
LIB.seccomp_release.argtypes = [ctypes.c_void_p]
LIBC.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]


def install_filter() -> int:
    if LIBC.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
    context = LIB.seccomp_init(SCMP_ACT_ALLOW)
    if not context:
        raise OSError(ctypes.get_errno(), "seccomp_init")
    if LIB.seccomp_rule_add(context, SCMP_ACT_NOTIFY, SCMP_SYS_OPENAT, 0) != 0:
        raise OSError(ctypes.get_errno(), "seccomp_rule_add")
    if LIB.seccomp_load(context) != 0:
        raise OSError(ctypes.get_errno(), "seccomp_load")
    listener = LIB.seccomp_notify_fd(context)
    if listener < 0:
        raise OSError(ctypes.get_errno(), "seccomp_notify_fd")
    LIB.seccomp_release(context)
    return listener


def child(sock: socket.socket, case: str, secret: str) -> None:
    try:
        listener = install_filter()
        sock.sendmsg([case.encode()], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [listener]))])
        results = []
        for _ in range(2):
            try:
                fd = os.open(secret, os.O_RDONLY)
                os.close(fd)
                results.append({"open_result": "allowed", "errno": None})
            except OSError as error:
                results.append({"open_result": "denied", "errno": error.errno})
        sock.send(json.dumps({"attempts": results}).encode())
    except BaseException as error:
        sock.send(json.dumps({"error": str(error)}).encode())
    finally:
        os._exit(0)


def gateway_event(gateway: subprocess.Popen[str], event: dict[str, object]) -> dict[str, object]:
    assert gateway.stdin is not None and gateway.stdout is not None
    gateway.stdin.write(json.dumps(event, separators=(",", ":")) + "\n")
    gateway.stdin.flush()
    if not select.select([gateway.stdout], [], [], BROKER_TIMEOUT_S)[0]:
        raise TimeoutError("agb-gateway response timeout")
    line = gateway.stdout.readline()
    if not line:
        raise RuntimeError(gateway.stderr.read() if gateway.stderr else "gateway stopped")
    return json.loads(line)


def subject_for(pid: int, executable: str) -> dict[str, object]:
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
        "exe": executable,
    }


def make_event(case: str, sequence: int, subject: dict[str, object], operation: str,
               resource: dict[str, object], result: str, labels: list[str]) -> dict[str, object]:
    namespace = f"process:{subject['boot_id']}:{subject['pid']}:{subject['start_time_ns']}"
    return {
        "schema_version": "1.0",
        "event_id": f"evt:seccomp-{case}-{sequence}",
        "sequence": sequence,
        "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "monotonic_ns": time.monotonic_ns(),
        "host_id": "host:seccomp-lab",
        "namespace_id": namespace,
        "subject": subject,
        "operation": operation,
        "resource": resource,
        "result": result,
        "policy_revision": "policy:seccomp-causal-v1",
        "labels": labels,
        "provenance": {"source": "agent-broker", "case": case},
    }


def broker(sock: socket.socket, pid: int, secret: str,
           gateway: subprocess.Popen[str]) -> dict[str, object]:
    message, ancdata, *_ = sock.recvmsg(64, socket.CMSG_LEN(array.array("i").itemsize))
    case = message.decode()
    received = array.array("i")
    for level, kind, data in ancdata:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            received.frombytes(data[: received.itemsize])
    if not received:
        raise RuntimeError("broker did not receive seccomp listener")
    listener = received[0]
    subject = subject_for(pid, "seccomp-lab-workload")
    cache = DecisionCache(ttl_seconds=2.0)
    gateway_error = None
    try:
        gateway_event(gateway, make_event(case, 1, subject, "process.exec",
                                           {"type": "process", "path": subject["exe"]},
                                           "allowed", []))
        if case == "benign":
            gateway_event(gateway, make_event(case, 2, subject, "file.open",
                                               {"type": "file", "path": "/tmp/agent.conf"},
                                               "allowed", ["configuration"]))
        else:
            gateway_event(gateway, make_event(case, 2, subject, "network.connect",
                                               {"type": "network", "host": "127.0.0.1", "port": 9},
                                               "allowed", ["external"]))
    except Exception as error:
        gateway_error = str(error)
    namespace = f"process:{subject['boot_id']}:{subject['pid']}:{subject['start_time_ns']}"
    cache_key = (namespace, secret, "trajectory")
    decision_response = None
    effect = None
    event_id = None
    cache_hits = 0
    notification_ids = []
    for attempt in range(2):
        if not select.select([listener], [], [], BROKER_TIMEOUT_S)[0]:
            raise TimeoutError("seccomp notification timeout")
        notification = bytearray(80)
        fcntl.ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, notification, True)
        event_id = struct.unpack_from("<Q", notification)[0]
        if event_id == 0:
            raise RuntimeError("invalid seccomp notification id")
        notification_ids.append(event_id)
        if attempt == 0:
            if gateway_error is None:
                try:
                    decision_response = gateway_event(
                        gateway,
                        make_event(case, 3, subject, "file.open",
                                   {"type": "file", "path": secret}, "requested", ["credential"]),
                    )
                except Exception as error:
                    gateway_error = str(error)
            if gateway_error is not None:
                decision_response = {
                    "decision": {
                        "effect": "DENY",
                        "policy_revision": "policy:fallback-fail-closed",
                        "reason_codes": ["AGB_GATEWAY_UNAVAILABLE"],
                        "evidence_ids": [],
                    },
                    "enforcement": {"backend": "seccomp-user-notify", "applied": True},
                }
            effect = decision_response["decision"]["effect"]
            cache.put(cache_key, effect, decision_response["decision"]["policy_revision"])
        else:
            cached = cache.get(cache_key, decision_response["decision"]["policy_revision"])
            if cached is None:
                raise RuntimeError("decision cache unexpectedly missed")
            effect = cached
            cache_hits += 1
        if effect not in {"ALLOW", "DENY"}:
            raise RuntimeError(f"unsupported gateway effect: {effect}")
        response = struct.pack(
            "<Qqii", event_id, 0,
            -errno.EACCES if effect == "DENY" else 0,
            0 if effect == "DENY" else SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        )
        fcntl.ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response)
    child_result = json.loads(sock.recv(4096))
    return {
        "case": case,
        "broker": "seccomp-user-notify",
        "listener_received": True,
        "notification_id": notification_ids[0],
        "notification_ids": notification_ids,
        "shadow_effect": effect,
        "decision": decision_response["decision"],
        "gateway_enforcement": decision_response["enforcement"],
        "fallback": gateway_error is not None,
        "fallback_reason": gateway_error,
        "external_enforcement": {
            "backend": "seccomp-user-notify",
            "requested_effect": effect,
            "applied": effect == "DENY",
            "notification_id": notification_ids[0],
            "timeout_ms": int(BROKER_TIMEOUT_S * 1000),
            "cache_hit": cache_hits > 0,
            "cache_hits": cache_hits,
        },
        "enforcement_applied": effect == "DENY",
        **child_result,
    }


def run_case(case: str, secret: str, root: Path) -> dict[str, object]:
    left, right = socket.socketpair()
    pid = os.fork()
    if pid == 0:
        left.close()
        child(right, case, secret)
    right.close()
    store = root / f"{case}.events.jsonl"
    gateway = subprocess.Popen(
        ["target/debug/agb-gateway", "--store", str(store)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    try:
        result = broker(left, pid, secret, gateway)
        _, status = os.waitpid(pid, 0)
        if status != 0:
            raise RuntimeError(f"workload exited with status {status}")
        return result
    finally:
        if gateway.stdin:
            gateway.stdin.close()
        gateway.wait(timeout=5)
        left.close()


def main() -> None:
    output = Path("var/seccomp-proof")
    output.mkdir(parents=True, exist_ok=True)
    (output / "benign.events.jsonl").unlink(missing_ok=True)
    (output / "suspicious.events.jsonl").unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="agb-seccomp-proof-") as directory:
        secret = Path(directory) / "api-token"
        secret.write_text("laboratory-secret\n")
        report = {
            "proof": "external-seccomp-user-notify-v1",
            "gateway_store": str(output),
            "benign": run_case("benign", str(secret), output),
            "suspicious": run_case("suspicious", str(secret), output),
        }
    if any(attempt["open_result"] != "allowed" for attempt in report["benign"]["attempts"]):
        raise SystemExit("benign operation was not allowed")
    if any(attempt["open_result"] != "denied" for attempt in report["suspicious"]["attempts"]):
        raise SystemExit("suspicious operation was not denied")
    report_path = output / "REPORT.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print(f"report={report_path}")


if __name__ == "__main__":
    main()
