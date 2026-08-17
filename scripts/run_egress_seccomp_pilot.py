#!/usr/bin/env python3
"""Reversible seccomp-user-notify egress pilot for a disposable curl process."""

from __future__ import annotations

import argparse
import array
import ctypes
import errno
import fcntl
import json
import os
import select
import socket
import struct
import subprocess
import time
from pathlib import Path
from typing import Any

from agb_fake_asm.egress_policy import ExecutableEgressPolicy
from agb_fake_asm.enforcement_scope import (
    ArtifactIdentity,
    ExecutableProcessScope,
    ProcessIdentity,
    enforcement_effect,
    process_tgid,
)
from bpf_to_events import decode_sockaddr

LIB = ctypes.CDLL("libseccomp.so.2", use_errno=True)
LIBC = ctypes.CDLL(None, use_errno=True)
SCMP_ACT_NOTIFY = 0x7FC00000
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_SYS_CONNECT_X86_64 = 42
SECCOMP_IOCTL_NOTIF_RECV = 0xC0502100
SECCOMP_IOCTL_NOTIF_SEND = 0xC0182101
SECCOMP_IOCTL_NOTIF_ID_VALID = 0x40082102
SECCOMP_USER_NOTIF_FLAG_CONTINUE = 1
NOTIFICATION = struct.Struct("<QIIiIQQQQQQQ")

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
    try:
        if LIB.seccomp_rule_add(context, SCMP_ACT_NOTIFY, SCMP_SYS_CONNECT_X86_64, 0) != 0:
            raise OSError(ctypes.get_errno(), "seccomp_rule_add(connect)")
        if LIB.seccomp_load(context) != 0:
            raise OSError(ctypes.get_errno(), "seccomp_load")
        listener = LIB.seccomp_notify_fd(context)
        if listener < 0:
            raise OSError(ctypes.get_errno(), "seccomp_notify_fd")
        return listener
    finally:
        LIB.seccomp_release(context)


def filtered_curl(channel: socket.socket, curl: Path, url: str) -> None:
    try:
        listener = install_filter()
        channel.sendmsg([b"ready"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [listener]))])
        release_read, release_write = os.pipe()
        curl_pid = os.fork()
        if curl_pid == 0:
            os.close(release_write)
            if os.read(release_read, 1) != b"G":
                os._exit(126)
            os.close(release_read)
            os.execv(str(curl), [str(curl), "--silent", "--show-error", "--max-time", "4", url])
        os.close(release_read)
        channel.send(json.dumps({"target_pid": curl_pid}).encode())
        if channel.recv(16) != b"GO":
            os.kill(curl_pid, 9)
            os._exit(126)
        out_of_scope_probe_allowed = False
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("198.51.100.1", 443))
            out_of_scope_probe_allowed = True
        finally:
            probe.close()
        os.write(release_write, b"G")
        os.close(release_write)
        _, status = os.waitpid(curl_pid, 0)
        exit_code = os.waitstatus_to_exitcode(status)
        channel.send(json.dumps({
            "exit_code": exit_code,
            "out_of_scope_probe_allowed": out_of_scope_probe_allowed,
        }).encode())
        os._exit(exit_code)
    except BaseException as error:
        channel.send(json.dumps({"error": str(error)}).encode())
        os._exit(125)


def receive_listener(channel: socket.socket) -> int:
    message, ancillary, *_ = channel.recvmsg(64, socket.CMSG_LEN(array.array("i").itemsize))
    if message != b"ready":
        raise RuntimeError(f"filtered child failed before exec: {message.decode(errors='replace')}")
    descriptors = array.array("i")
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            descriptors.frombytes(data[: descriptors.itemsize])
    if not descriptors:
        raise RuntimeError("seccomp listener was not received")
    return descriptors[0]


def read_sockaddr(pid: int, address: int, length: int) -> dict[str, object]:
    if not 2 <= length <= 128:
        raise ValueError("invalid sockaddr length")
    memory = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        raw = os.pread(memory, length, address)
    finally:
        os.close(memory)
    if len(raw) != length:
        raise ValueError("truncated sockaddr from notified process")
    return decode_sockaddr(raw.hex())


def notification_is_valid(listener: int, notification_id: int) -> bool:
    try:
        fcntl.ioctl(
            listener,
            SECCOMP_IOCTL_NOTIF_ID_VALID,
            bytearray(struct.pack("<Q", notification_id)),
            True,
        )
        return True
    except OSError as error:
        if error.errno == errno.ENOENT:
            return False
        raise


def supervise(curl: Path, url: str, policy: ExecutableEgressPolicy) -> dict[str, Any]:
    parent, child = socket.socketpair(type=socket.SOCK_SEQPACKET)
    pid = os.fork()
    if pid == 0:
        parent.close()
        os.setpgid(0, 0)
        filtered_curl(child, curl, url)
    child.close()
    listener = receive_listener(parent)
    target_message = json.loads(parent.recv(4096))
    target_pid = int(target_message["target_pid"])
    scope = ExecutableProcessScope(target_pid, ArtifactIdentity.from_path(curl))
    parent.send(b"GO")
    decisions = []
    stale_notifications = 0
    invalid_notification_ids = 0
    try:
        while True:
            ready, _, _ = select.select([parent, listener], [], [], 0.1)
            if parent in ready:
                payload = parent.recv(4096)
                if not payload:
                    raise RuntimeError("filtered curl exited without reporting status")
                status_report = json.loads(payload)
                _, status = os.waitpid(pid, 0)
                exit_code = os.waitstatus_to_exitcode(status)
                if exit_code != status_report.get("exit_code"):
                    raise RuntimeError("filtered curl status handshake mismatch")
                return {
                    "url": url,
                    "exit_code": exit_code,
                    "decisions": decisions,
                    "stale_notifications": stale_notifications,
                    "invalid_notification_ids": invalid_notification_ids,
                    "out_of_scope_probe_allowed": status_report.get(
                        "out_of_scope_probe_allowed", False
                    ),
                }
            if listener not in ready:
                continue
            notification = bytearray(NOTIFICATION.size)
            try:
                fcntl.ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, notification, True)
            except OSError as error:
                if error.errno in {errno.ENOENT, errno.EINTR}:
                    stale_notifications += 1
                    continue
                raise
            values = NOTIFICATION.unpack(notification)
            notification_id, notified_pid = values[0], values[1]
            args = values[6:]
            if not notification_is_valid(listener, notification_id):
                invalid_notification_ids += 1
                continue
            started_ns = time.monotonic_ns()
            try:
                notified_tgid = process_tgid(notified_pid)
            except (OSError, ValueError):
                notified_tgid = -1
            target_notification = notified_tgid == target_pid
            adapter_failed = False
            identity_reason = "PID_OUT_OF_SCOPE"
            try:
                resource = read_sockaddr(notified_pid, args[1], args[2])
                resource["type"] = "network"
                resource["fd"] = args[0]
                executable = os.readlink(f"/proc/{notified_pid}/exe")
                if target_notification:
                    identity = ProcessIdentity.from_pid(
                        notified_pid, include_hash=scope.pinned is None
                    )
                    identity_valid, identity_reason = scope.bind_or_verify(identity)
                    if not identity_valid:
                        adapter_failed = True
                event = {
                    "operation": "network.connect",
                    "result": "requested",
                    "subject": {"exe": executable},
                    "resource": resource,
                }
                decision = policy.evaluate(event)
            except (OSError, ValueError) as error:
                resource = {"type": "network", "decode_error": str(error)}
                executable = "<unavailable>"
                decision = {"effect": "ABSTAIN", "reason": "DESTINATION_DECODE_FAILED"}
                adapter_failed = True
            decision_latency_us = (time.monotonic_ns() - started_ns) // 1_000
            decision_timed_out = decision_latency_us > 100_000
            effect = enforcement_effect(
                decision["effect"],
                target_pid=target_notification,
                adapter_failed=adapter_failed,
                timed_out=decision_timed_out,
            )
            deny = effect == "DENY"
            if not notification_is_valid(listener, notification_id):
                invalid_notification_ids += 1
                continue
            response = struct.pack(
                "<Qqii",
                notification_id,
                0,
                -errno.EACCES if deny else 0,
                0 if deny else SECCOMP_USER_NOTIF_FLAG_CONTINUE,
            )
            fcntl.ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response)
            decisions.append({
                "executable": executable,
                "resource": resource,
                "effect": "DENY" if deny else decision["effect"],
                "policy_effect": decision["effect"],
                "reason": decision["reason"],
                "identity_reason": identity_reason,
                "target_pid": target_notification,
                "notified_tid": notified_pid,
                "notified_tgid": notified_tgid,
                "decision_latency_us": decision_latency_us,
                "adapter_failed": adapter_failed,
                "decision_timed_out": decision_timed_out,
                "errno": errno.EACCES if deny else None,
                "enforcement_applied": deny,
            })
    finally:
        os.close(listener)
        parent.close()
        try:
            os.killpg(pid, 9)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass


def loopback_server() -> tuple[socket.socket, int, int]:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    pid = os.fork()
    if pid == 0:
        connection, _ = server.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        os._exit(0)
    return server, server.getsockname()[1], pid


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--curl", type=Path, default=Path("/usr/bin/curl"))
    parser.add_argument("--external-url", default="https://example.com")
    parser.add_argument("--output", type=Path, default=Path("var/benchmark/gate4-curl-egress-pilot.json"))
    args = parser.parse_args()
    curl = args.curl.resolve()
    if not curl.is_file():
        parser.error(f"curl executable not found: {curl}")
    scope_artifact = ArtifactIdentity.from_path(curl)
    policy = ExecutableEgressPolicy(str(curl))
    server, port, server_pid = loopback_server()
    try:
        loopback = supervise(curl, f"http://127.0.0.1:{port}", policy)
    except BaseException:
        try:
            os.kill(server_pid, 9)
        except ProcessLookupError:
            pass
        os.waitpid(server_pid, 0)
        raise
    finally:
        server.close()
    _, server_status = os.waitpid(server_pid, 0)
    if server_status != 0:
        raise RuntimeError("loopback test server failed")
    external = supervise(curl, args.external_url, policy)
    if loopback["exit_code"] != 0 or any(item["effect"] == "DENY" for item in loopback["decisions"]):
        raise RuntimeError("loopback was not preserved")
    external_denials = [item for item in external["decisions"] if item["effect"] == "DENY"]
    if external["exit_code"] == 0 or not external_denials:
        raise RuntimeError("external curl was not denied")
    for result in (loopback, external):
        out_of_scope = [
            item for item in result["decisions"] if not item["target_pid"]
        ]
        if not result["out_of_scope_probe_allowed"] or not any(
            item["effect"] == "ALLOW"
            and item["resource"].get("address") == "198.51.100.1"
            and not item["enforcement_applied"]
            for item in out_of_scope
        ):
            raise RuntimeError("out-of-scope executable isolation was not proven")
    report = {
        "proof": "unix-agb-executable-egress-seccomp-pilot-v2",
        "scope": str(curl),
        "identity_binding": {
            "path": scope_artifact.path,
            "device": scope_artifact.device,
            "inode": scope_artifact.inode,
            "sha256": scope_artifact.sha256,
            "process_fields": ["tgid", "start_time_ns"],
        },
        "loopback": loopback,
        "external": external,
        "external_denials": len(external_denials),
        "denied_errno": errno.EACCES,
        "system_wide_changes": False,
        "rollback": "filtered curl process exited; seccomp filter and listener were destroyed",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
