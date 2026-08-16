#!/usr/bin/env python3
"""Run one process-local, expiring and reversible Gate 4 denial proof."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def process_identity(pid: int) -> tuple[str, int, str]:
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    fields = Path(f"/proc/{pid}/stat").read_text().split()
    ticks = int(fields[21])
    ticks_per_second = os.sysconf("SC_CLK_TCK")
    start_ns = ticks * 1_000_000_000 // ticks_per_second
    exe = str(Path(f"/proc/{pid}/exe").resolve())
    return boot_id, start_ns, exe


def workload_command(binary: Path, lab: Path, *, hold: bool) -> list[str]:
    command = [
        str(binary),
        "--case", "benign",
        "--family", "credential-egress",
        "--secret", str(lab / "protected-secret.txt"),
        "--config", str(lab / "benign-config.txt"),
        "--persistence-origin", str(lab / "unused-origin"),
        "--persistence-target", str(lab / "unused-target"),
        "--admin-origin", str(lab / "unused-admin-origin"),
        "--admin-target", str(lab / "unused-admin-target"),
        "--port", "9",
    ]
    if hold:
        command.append("--hold-for-release")
    return command


def start_workload(binary: Path, lab: Path, *, hold: bool) -> tuple[subprocess.Popen[str], dict]:
    process = subprocess.Popen(
        workload_command(binary, lab, hold=hold),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert process.stdin is not None and process.stdout is not None
    line = process.stdout.readline()
    if not line:
        raise RuntimeError(f"laboratory workload failed before ready: {process.stderr.read()}")
    ready = json.loads(line)
    if ready.get("ready") is not True or ready.get("pid") != process.pid:
        raise RuntimeError("laboratory workload readiness identity mismatch")
    return process, ready


def gate3_deny(policy_binary: Path, pid: int, secret: Path, lab: Path, ttl: int) -> dict:
    boot_id, start_ns, exe = process_identity(pid)
    namespace = f"process:{boot_id}:{pid}:{start_ns}"
    occurred_at = "2026-08-16T12:00:00Z"
    event = {
        "schema_version": "1.0",
        "event_id": f"evt:gate4:{pid}:1",
        "sequence": 1,
        "occurred_at": occurred_at,
        "monotonic_ns": time.monotonic_ns(),
        "host_id": "host:gate4-lab",
        "namespace_id": namespace,
        "subject": {
            "pid": pid,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "boot_id": boot_id,
            "start_time_ns": start_ns,
            "exe": exe,
            "service": None,
            "container_id": None,
            "agent_id": None,
        },
        "operation": "file.open",
        "resource": {"type": "file", "path": str(secret), "access": "read"},
        "result": "requested",
        "policy_revision": "policy:gate4-lab-v1",
        "labels": ["gate4-controlled-marker"],
        "provenance": {"source": "synthetic", "laboratory": True},
    }
    state = {
        "schema_version": "1.0",
        "namespace_id": namespace,
        "state_revision": 1,
        "risk_band": "restricted",
        "confidence": 1.0,
        "signals": ["gate4-controlled-marker"],
        "evidence_ids": [event["event_id"]],
        "engine": "fake",
        "checkpoint_fingerprint": None,
        "updated_at": occurred_at,
    }
    environment = {
        **os.environ,
        "AGB_GATE3_POLICY_REVISION": "policy:gate4-lab-v1",
        "AGB_GATE3_CACHE_KEY": "gate4-ephemeral-lab-key",
        "AGB_GATE3_TTL_SECONDS": str(ttl),
        "AGB_GATE3_AUDIT_GROUP_SIZE": "64",
    }
    completed = subprocess.run(
        [str(policy_binary), str(lab / "gate4-audit.jsonl"), str(lab / "gate4-cache.json")],
        input=json.dumps({"event": event, "state": state}) + "\n",
        text=True,
        capture_output=True,
        env=environment,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Gate 3 failed: {completed.stderr}")
    response = json.loads(completed.stdout)
    if response["decision"]["effect"] != "DENY" or response["enforcement_applied"] is not False:
        raise RuntimeError("Gate 3 did not produce the expected dry-run DENY")
    snapshot = json.loads((lab / "gate4-cache.json").read_text())
    if len(snapshot["entries"]) != 1 or snapshot["entries"][0]["effect"] != "DENY":
        raise RuntimeError("Gate 4 input cache is not exactly one DENY")
    return {"response": response, "entry": snapshot["entries"][0]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workload-bin", type=Path, default=ROOT / "target/debug/agb-lab-workload")
    parser.add_argument("--policy-bin", type=Path, default=ROOT / "target/debug/agb-policy-dry-run")
    parser.add_argument("--ttl-seconds", type=int, default=2)
    parser.add_argument("--output", type=Path, default=ROOT / "var/benchmark/gate4-reversible-denial.json")
    args = parser.parse_args()
    if not 1 <= args.ttl_seconds <= 10:
        parser.error("--ttl-seconds must be between 1 and 10 for the controlled pilot")
    for binary in (args.workload_bin, args.policy_bin):
        if not binary.is_file():
            parser.error(f"binary not found: {binary}")

    with tempfile.TemporaryDirectory(prefix="unix-agb-gate4-") as temporary:
        lab = Path(temporary)
        (lab / "protected-secret.txt").write_text("controlled marker only\n")
        (lab / "benign-config.txt").write_text("benign laboratory config\n")
        for name in ("unused-origin", "unused-target", "unused-admin-origin", "unused-admin-target"):
            (lab / name).write_text("unused\n")

        denied_process, _ = start_workload(args.workload_bin, lab, hold=True)
        gate3 = gate3_deny(
            args.policy_bin, denied_process.pid, lab / "protected-secret.txt", lab, args.ttl_seconds
        )
        assert denied_process.stdin is not None and denied_process.stdout is not None
        denied_process.stdin.write("DENY\n")
        denied_process.stdin.flush()
        denied = json.loads(denied_process.stdout.readline())
        if denied.get("open_result") != "denied":
            denied_process.kill()
            raise RuntimeError(f"controlled denial was not applied: {denied}")

        expires_epoch = int(gate3["entry"]["expires_epoch"])
        wait_seconds = max(0.0, expires_epoch - time.time() + 0.05)
        time.sleep(wait_seconds)
        expired_before_rollback = time.time() >= expires_epoch
        denied_process.stdin.write("RELEASE\n")
        denied_process.stdin.flush()
        denied_process.wait(timeout=5)
        if denied_process.returncode != 0:
            raise RuntimeError(f"denied workload teardown failed: {denied_process.stderr.read()}")

        allowed_process, _ = start_workload(args.workload_bin, lab, hold=False)
        assert allowed_process.stdin is not None and allowed_process.stdout is not None
        allowed_process.stdin.write("ALLOW\n")
        allowed_process.stdin.flush()
        allowed = json.loads(allowed_process.stdout.readline())
        allowed_process.wait(timeout=5)
        if allowed_process.returncode != 0 or allowed.get("open_result") != "allowed":
            raise RuntimeError("clean replacement process did not restore baseline access")

        report = {
            "proof": "unix-agb-gate4-reversible-denial-v1",
            "scope": "one process-local laboratory workload and one temporary marker file",
            "policy_revision": "policy:gate4-lab-v1",
            "ttl_seconds": args.ttl_seconds,
            "deny_audit_preceded_cache": True,
            "compiled_cache_effect": gate3["entry"]["effect"],
            "gate3_enforcement_applied": gate3["response"]["enforcement_applied"],
            "gate4_enforcement_applied": True,
            "denied_errno": denied.get("errno"),
            "cache_expired_before_rollback": expired_before_rollback,
            "rollback": "terminate restricted process and start a clean process",
            "post_rollback_access": allowed["open_result"],
            "system_wide_changes": False,
            "limitations": "Landlock restriction is irreversible inside the original process; rollback is process teardown. No production workload or system path is targeted.",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
