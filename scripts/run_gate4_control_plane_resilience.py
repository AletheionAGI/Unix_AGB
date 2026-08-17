#!/usr/bin/env python3
"""Reversible control-plane proofs for Gate 4 supervision."""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import tempfile
import time
from pathlib import Path

from agb_fake_asm.guardian_resilience import HandoffAuthenticator, RestartBudget
from run_gate4_prelease_teardown import process_exists, terminate_group

POLICY_REVISION = "policy:gate4-egress-guardian-v1"
LAB_SECRET = b"G4-lab-handoff-key-32-bytes!!!!!"


def peer_credentials(channel: socket.socket) -> tuple[int, int, int]:
    return struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))


def authenticated_handoff_proof() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="unix-agb-gate4-auth-") as directory:
        path = Path(directory) / "handoff.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        server.bind(str(path))
        server.listen(1)
        child = os.fork()
        if child == 0:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            client.connect(str(path))
            auth = HandoffAuthenticator(LAB_SECRET, POLICY_REVISION, os.getuid(), os.getgid())
            message = auth.sign(pid=os.getpid(), uid=os.getuid(), gid=os.getgid(), nonce="handoff-generation-1", expires_ns=time.monotonic_ns() + 1_000_000_000)
            client.send(json.dumps(message).encode())
            client.send(json.dumps(message).encode())
            stale = dict(message); stale["policy_revision"] = "policy:stale"
            client.send(json.dumps(stale).encode())
            os._exit(0)
        connection, _ = server.accept()
        peer_pid, peer_uid, peer_gid = peer_credentials(connection)
        verifier = HandoffAuthenticator(LAB_SECRET, POLICY_REVISION, os.getuid(), os.getgid())
        results = []
        for _ in range(3):
            message = json.loads(connection.recv(4096))
            results.append(verifier.verify(message, peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid, now_ns=time.monotonic_ns()))
        os.waitpid(child, 0)
        connection.close(); server.close()
    return {"peer": {"pid": peer_pid, "uid": peer_uid, "gid": peer_gid}, "results": [{"accepted": accepted, "reason": reason} for accepted, reason in results]}


def spawn_sleeper(*, process_group: bool) -> int:
    pid = os.fork()
    if pid == 0:
        if process_group:
            os.setpgid(0, 0)
        time.sleep(30)
        os._exit(0)
    return pid


def restart_budget_proof() -> dict[str, object]:
    protected = spawn_sleeper(process_group=True)
    unrelated = spawn_sleeper(process_group=False)
    budget = RestartBudget(maximum=2, window_seconds=60)
    outcomes = []
    for attempt in range(1, 4):
        worker = os.fork()
        if worker == 0:
            os._exit(70)
        _, status = os.waitpid(worker, 0)
        admitted = budget.consume(float(attempt))
        outcomes.append({"attempt": attempt, "worker_exit": os.waitstatus_to_exitcode(status), "restart_admitted": admitted})
        if not admitted:
            teardown = terminate_group(protected, grace_ms=20)
            break
    os.waitpid(protected, 0)
    unrelated_survived = process_exists(unrelated)
    os.kill(unrelated, 9); os.waitpid(unrelated, 0)
    return {"maximum_restarts": 2, "outcomes": outcomes, "teardown": teardown, "protected_terminated": not process_exists(protected), "unrelated_survived": unrelated_survived}


def guardian_death_proof() -> dict[str, object]:
    protected = spawn_sleeper(process_group=True)
    unrelated = spawn_sleeper(process_group=False)
    guardian = os.fork()
    if guardian == 0:
        os._exit(73)
    detected_ns = time.monotonic_ns()
    _, status = os.waitpid(guardian, 0)
    teardown = terminate_group(protected, grace_ms=20)
    response_us = (time.monotonic_ns() - detected_ns) // 1_000
    os.waitpid(protected, 0)
    unrelated_survived = process_exists(unrelated)
    os.kill(unrelated, 9); os.waitpid(unrelated, 0)
    return {"guardian_exit": os.waitstatus_to_exitcode(status), "launcher_response_us": response_us, "teardown": teardown, "protected_terminated": not process_exists(protected), "unrelated_survived": unrelated_survived}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("var/benchmark/gate4-control-plane-resilience.json"))
    args = parser.parse_args()
    auth = authenticated_handoff_proof()
    budget = restart_budget_proof()
    guardian = guardian_death_proof()
    report = {
        "proof": "unix-agb-gate4-control-plane-resilience-v1",
        "policy_revision": POLICY_REVISION,
        "authenticated_handoff": auth,
        "restart_budget": budget,
        "guardian_death": guardian,
        "system_wide_changes": False,
        "criteria": {
            "handoff_authenticated": auth["results"][0] == {"accepted": True, "reason": "HANDOFF_AUTHENTICATED"},
            "replay_rejected": auth["results"][1]["reason"] == "HANDOFF_REPLAY",
            "stale_revision_rejected": auth["results"][2]["reason"] == "POLICY_REVISION_MISMATCH",
            "restart_budget_enforced": [item["restart_admitted"] for item in budget["outcomes"]] == [True, True, False],
            "budget_teardown_scoped": budget["protected_terminated"] and budget["unrelated_survived"],
            "guardian_death_teardown_scoped": guardian["guardian_exit"] == 73 and guardian["protected_terminated"] and guardian["unrelated_survived"],
            "system_wide_changes": False,
        },
        "limitations": ["Process groups stand in for delegated production cgroups.", "The launcher proof is process-local and does not install a boot-persistent service."],
    }
    if not all(value for key, value in report["criteria"].items() if key != "system_wide_changes"):
        raise RuntimeError(f"control-plane criteria failed: {report['criteria']}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
