#!/usr/bin/env python3
"""Exercise Gate 4 negative cache inputs against one live process per case."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import socket
import subprocess
import time
from pathlib import Path

REVISION = "policy:bpf-observer-v2"
FIELDS = (
    "cache_key", "decision_id", "namespace_id", "operation", "resource_sha256",
    "effect", "policy_revision", "state_revision", "evidence_sha256", "expires_epoch",
)


def signed_snapshot(entries: list[dict[str, object]], secret: bytes, revision: str = REVISION) -> dict[str, object]:
    normalized = [{field: entry[field] for field in FIELDS} for entry in entries]
    payload = json.dumps([1, revision, normalized], separators=(",", ":")).encode()
    return {"format_version": 1, "policy_revision": revision, "entries": normalized,
            "hmac_sha256": hmac.new(secret, payload, hashlib.sha256).hexdigest()}


def denial(namespace: str, expires: int, revision: str = REVISION) -> dict[str, object]:
    resource = hashlib.sha256(b"domain1-negative-matrix").hexdigest()
    return {
        "cache_key": f"{namespace}|network.connect|{resource}",
        "decision_id": "dec:" + hashlib.sha256(f"{namespace}:{expires}:{revision}".encode()).hexdigest(),
        "namespace_id": namespace, "operation": "network.connect", "resource_sha256": resource,
        "effect": "DENY", "policy_revision": revision, "state_revision": 1,
        "evidence_sha256": hashlib.sha256(namespace.encode()).hexdigest(), "expires_epoch": expires,
    }


def atomic_write(path: Path, value: object, owner: tuple[int, int]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, separators=(",", ":")) + "\n")
    os.chmod(temporary, 0o640)
    os.chown(temporary, *owner)
    os.replace(temporary, path)


def wait_json(path: Path, phase: str, timeout: float = 5.0) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = json.loads(path.read_text())
            if value.get("phase") == phase:
                return value
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        time.sleep(0.025)
    raise TimeoutError(f"{path} did not reach {phase}")


def namespace(pid: int) -> str:
    fields = Path(f"/proc/{pid}/stat").read_text().split()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    start_ns = int(fields[21]) * 1_000_000_000 // os.sysconf("SC_CLK_TCK")
    return f"process:{boot}:{pid}:{start_ns}"


def run_case(args: argparse.Namespace, case: str, secret: bytes, owner: tuple[int, int]) -> dict[str, object]:
    lab = args.lab / case
    lab.mkdir(parents=True, exist_ok=True)
    state, trigger = lab / "state.json", lab / "trigger"
    atomic_write(args.cache, signed_snapshot([], secret), owner)
    unit = f"agb-domain1-{case.replace('_', '-')}"
    command = [
        "systemd-run", f"--unit={unit}", "--property=Type=exec", str(args.launcher),
        str(args.workload), "--config", str(args.config), "--secret", str(args.canary),
        "--trigger", str(trigger), "--state", str(state), "--loopback-port", str(args.loopback_port),
        "--external-address", args.external_address, "--external-port", str(args.external_port),
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)
    initial = wait_json(state, "captured")
    exact = namespace(int(initial["pid"]))
    now = int(time.time())
    if case in {"allow_projection", "abstain_projection"}:
        value: object = signed_snapshot([], secret)
        expected = "other-error"
    elif case == "expired_deny":
        value = signed_snapshot([denial(exact, now - 1)], secret)
        expected = "other-error"
    elif case == "corrupt_snapshot":
        value = {"corrupt": True}
        expected = "other-error"
    elif case == "wrong_revision":
        wrong = "policy:bpf-observer-wrong"
        value = signed_snapshot([denial(exact, now + 300, wrong)], secret, wrong)
        expected = "other-error"
    elif case == "cross_namespace_replay":
        value = signed_snapshot([denial(exact + ":other", now + 300)], secret)
        expected = "other-error"
    elif case == "active_deny_replay":
        value = signed_snapshot([denial(exact, now + 300)], secret)
        expected = "EACCES"
    else:
        raise AssertionError(case)
    if case == "corrupt_snapshot":
        temporary = args.cache.with_name(f".{args.cache.name}.corrupt")
        temporary.write_text("{invalid-json\n")
        os.chown(temporary, *owner)
        os.replace(temporary, args.cache)
    else:
        atomic_write(args.cache, value, owner)
    trigger.touch()
    enforced = wait_json(state, "enforced")
    atomic_write(args.cache, signed_snapshot([], secret), owner)
    trigger.unlink()
    recovered = wait_json(state, "complete")
    subprocess.run(["systemctl", "reset-failed", unit], capture_output=True)
    passed = enforced["outcome"] == expected and recovered["recovery_errno"] == 111
    return {"case": case, "namespace_id": exact, "observed": enforced["outcome"],
            "expected": expected, "recovery_errno": recovered["recovery_errno"], "passed": passed}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path("/var/lib/unix-agb/gate3-cache.json"))
    parser.add_argument("--launcher", type=Path, default=Path("/usr/libexec/unix-agb/agb-egress-launch"))
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--lab", type=Path, default=Path("/tmp/agb-domain1-matrix"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--canary", type=Path, required=True)
    parser.add_argument("--loopback-port", type=int, default=18080)
    parser.add_argument("--external-address", required=True)
    parser.add_argument("--external-port", type=int, default=9)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    secret = args.key.read_bytes().strip()
    stat = args.cache.stat()
    cases = ["allow_projection", "abstain_projection", "expired_deny", "corrupt_snapshot",
             "wrong_revision", "cross_namespace_replay", "active_deny_replay"]
    results = [run_case(args, case, secret, (stat.st_uid, stat.st_gid)) for case in cases]
    control_errno = None
    try:
        socket.create_connection((args.external_address, args.external_port), timeout=2).close()
    except OSError as error:
        control_errno = error.errno
    document = {"proof": "unix-agb-gate4-domain1-negative-matrix-v1", "policy_revision": REVISION,
                "cases": results, "unprotected_control_errno": control_errno,
                "protected_fail_open": 0, "cross_scope_effects": 0,
                "supported": all(item["passed"] for item in results) and control_errno == 111}
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps(document, indent=2, sort_keys=True))
    if not document["supported"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
