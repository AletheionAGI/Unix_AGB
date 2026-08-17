#!/usr/bin/env python3
"""Run Gate 4 proofs inside reversible user-systemd transient cgroups."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=check)


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def wait_for(predicate, timeout: float, description: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise TimeoutError(description)


def unit_cgroup(unit: str) -> str:
    return run(["systemctl", "--user", "show", unit, "--property=ControlGroup", "--value"]).stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recovery-deadline-ms", type=int, default=50)
    parser.add_argument("--output", type=Path, default=Path("var/benchmark/gate4-transient-cgroup.json"))
    args = parser.parse_args()
    token = uuid.uuid4().hex[:12]
    seccomp_unit = f"unix-agb-g4-seccomp-{token}.service"
    teardown_unit = f"unix-agb-g4-teardown-{token}.service"
    inner_report = (ROOT / "var/benchmark/gate4-transient-cgroup-seccomp.json").resolve()
    state = (ROOT / "var/benchmark/gate4-transient-cgroup-state.json").resolve()
    for path in (inner_report, state):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    unrelated = subprocess.Popen(["sleep", "30"])
    rollback = {"seccomp_unit_collected": False, "teardown_unit_collected": False}
    try:
        seccomp = run([
            "systemd-run", "--user", "--wait", "--collect", "--quiet",
            f"--unit={seccomp_unit}", "--property=Type=exec", "--property=NoNewPrivileges=yes",
            "/usr/bin/env", f"PYTHONPATH={ROOT / 'python'}:{ROOT / 'scripts'}", "/usr/bin/python3",
            str(ROOT / "scripts/run_gate4_inflight_crash.py"), "--attempts", "64", "--threads", "8", "--output", str(inner_report),
        ], check=False)
        if seccomp.returncode != 0 or not inner_report.exists():
            raise RuntimeError(f"transient seccomp unit failed: {seccomp.stderr or seccomp.stdout}")
        inner = json.loads(inner_report.read_text())
        run([
            "systemd-run", "--user", "--collect", "--quiet", f"--unit={teardown_unit}",
            "--property=Type=exec", "--property=KillMode=control-group",
            "/usr/bin/python3", str(ROOT / "scripts/gate4_cgroup_workload.py"), "--state", str(state),
        ])
        wait_for(state.exists, 3, "transient workload did not publish state")
        workload = json.loads(state.read_text())
        control_group = unit_cgroup(teardown_unit)
        paths_match = all(path == control_group for path in workload["cgroups"].values())
        wait_for(lambda: not process_exists(int(workload["guardian_pid"])), 3, "guardian did not exit")
        failure_detected_ns = time.monotonic_ns()
        time.sleep(args.recovery_deadline_ms / 1000)
        cgroup_kill_path = Path("/sys/fs/cgroup") / control_group.lstrip("/") / "cgroup.kill"
        teardown_method = "cgroup.kill"
        try:
            cgroup_kill_path.write_text("1\n")
        except OSError:
            teardown_method = "systemctl-kill-control-group"
            run(["systemctl", "--user", "kill", "--kill-whom=all", "--signal=KILL", teardown_unit])
        teardown_us = (time.monotonic_ns() - failure_detected_ns) // 1_000
        wait_for(lambda: not process_exists(int(workload["launcher_pid"])), 3, "protected cgroup did not terminate")
        unrelated_survived = unrelated.poll() is None
        run(["systemctl", "--user", "reset-failed", teardown_unit], check=False)
        wait_for(lambda: run(["systemctl", "--user", "show", teardown_unit, "--property=LoadState", "--value"], check=False).stdout.strip() == "not-found", 3, "teardown unit was not collected")
        rollback["teardown_unit_collected"] = True
        rollback["seccomp_unit_collected"] = run(["systemctl", "--user", "show", seccomp_unit, "--property=LoadState", "--value"], check=False).stdout.strip() == "not-found"
        report = {
            "proof": "unix-agb-gate4-transient-cgroup-v1",
            "host": {"kernel": os.uname().release, "cgroup_version": 2},
            "units": {"seccomp": seccomp_unit, "teardown": teardown_unit, "control_group": control_group},
            "seccomp": inner["criteria"],
            "membership": {"pids": {key: workload[key] for key in ("launcher_pid", "guardian_pid", "broker_pid")}, "paths": workload["cgroups"], "all_match_control_group": paths_match},
            "teardown": {"deadline_ms": args.recovery_deadline_ms, "elapsed_us": teardown_us, "method": teardown_method, "unrelated_process_survived": unrelated_survived},
            "rollback": rollback,
            "system_wide_changes": False,
            "criteria": {
                "real_seccomp_completed_in_transient_unit": all(value for key, value in inner["criteria"].items() if key != "system_wide_changes"),
                "all_protected_members_in_exact_cgroup": paths_match,
                "guardian_failure_scoped_teardown": not process_exists(int(workload["launcher_pid"])) and unrelated_survived,
                "transient_units_collected": all(rollback.values()),
                "system_wide_changes": False,
            },
            "limitations": ["User-manager transient cgroups validate scoping but not a privileged system service.", "The host denied direct cgroup.kill if the recorded method is systemctl-kill-control-group."],
        }
        if not all(value for key, value in report["criteria"].items() if key != "system_wide_changes"):
            raise RuntimeError(f"transient cgroup criteria failed: {report['criteria']}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2, sort_keys=True))
    finally:
        for unit in (seccomp_unit, teardown_unit):
            run(["systemctl", "--user", "kill", "--kill-whom=all", "--signal=KILL", unit], check=False)
            run(["systemctl", "--user", "reset-failed", unit], check=False)
        if unrelated.poll() is None:
            unrelated.kill()
        unrelated.wait()


if __name__ == "__main__":
    main()
