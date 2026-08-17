#!/usr/bin/env python3
"""Freeze a host-bound Gate 4 formal manifest after prerequisite checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def executable(name: str) -> str:
    path = shutil.which(name)
    if not path:
        raise SystemExit(f"required executable is missing: {name}")
    return str(Path(path).resolve())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, default=Path("fixtures/benchmark/gate4-campaign-formal-profile.json"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-non-ubuntu", action="store_true", help="qualification only; never promotion evidence")
    args = parser.parse_args()
    raw = args.profile.read_bytes(); profile = json.loads(raw)
    os_release = platform.freedesktop_os_release()
    release = os_release.get("VERSION_ID", "unknown")
    if os_release.get("ID") != "ubuntu" and not args.allow_non_ubuntu:
        raise SystemExit("formal manifest must be frozen inside Ubuntu")
    if release not in profile["ubuntu_releases"] and not args.allow_non_ubuntu:
        raise SystemExit(f"Ubuntu {release} is outside the preregistered matrix")
    artifact = Path(profile["artifact_path"])
    if not artifact.is_file() or digest(artifact) != profile["artifact_sha256"]:
        raise SystemExit("frozen package is missing or has the wrong SHA-256")
    systemctl = executable("systemctl"); python = executable("python3")
    dbus = executable("dbus-daemon"); inhibit = executable("systemd-inhibit")
    service = profile["systemd_service"]
    active = subprocess.run([systemctl, "is-active", "--quiet", service], check=False).returncode == 0
    if not active and not args.allow_non_ubuntu:
        raise SystemExit(f"required long-lived service is not active: {service}")
    commands = {
        "python-http": [python, "-m", "http.server", "0", "--bind", "127.0.0.1"],
        "dbus-daemon": [dbus, "--session", "--nofork", "--nopidfile", "--nosyslog"],
        "systemd-inhibit": [inhibit, "--what=idle", "--mode=block", "--why=Unix-AGB Gate 4", "/usr/bin/sleep", "32400"],
    }
    workloads = []
    for class_name, count in profile["workload_counts"].items():
        for number in range(1, count + 1):
            workloads.append({"id": f"{class_name}-{number:02d}", "class": class_name,
                              "command": commands[class_name], "allow_early_exit": False})
    manifest = {
        "protocol": "unix-agb-gate4-automated-campaign-v1",
        "artifact_path": profile["artifact_path"], "artifact_sha256": profile["artifact_sha256"],
        "policy_revision": profile["policy_revision"],
        "domains": ["concurrency_endurance", "namespace_application_isolation",
                    "production_resource_latency", "real_application_coverage", "ubuntu_boot_matrix"],
        "application_classes": sorted(profile["workload_counts"]),
        "setup": [[systemctl, "is-active", "--quiet", service]],
        "workloads": workloads,
        "probes": [[systemctl, "is-active", "--quiet", service]],
        "teardown": [[systemctl, "is-active", "--quiet", service]],
        "artifacts": [profile["artifact_path"]],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    result = {"manifest": str(args.output), "manifest_sha256": digest(args.output),
              "profile_sha256": hashlib.sha256(raw).hexdigest(), "ubuntu_release": release,
              "workload_groups": len(workloads), "systemd_service_active": active,
              "qualification_only": bool(args.allow_non_ubuntu)}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
