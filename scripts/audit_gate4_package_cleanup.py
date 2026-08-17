#!/usr/bin/env python3
"""Audit that the Gate 4 lifecycle laboratory package left no host residue."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import grp
import subprocess
from pathlib import Path


PACKAGE = "unix-agb-egress-guardian-lab"
UNIT = "unix-agb-egress-guardian.service"
PATHS = (
    "/etc/unix-agb",
    "/etc/unix-agb/egress-guardian.json",
    "/etc/unix-agb/egress-guardian.enabled",
    "/etc/unix-agb/handoff.key",
    "/etc/unix-agb/gate3-cache.key",
    "/usr/lib/systemd/system/unix-agb-egress-guardian.service",
    "/usr/libexec/unix-agb",
    "/usr/libexec/unix-agb/agb-egress-guardian",
    "/usr/libexec/unix-agb/agb-egress-launch",
    "/usr/libexec/unix-agb/agb_gate3_runtime.py",
    "/usr/share/doc/unix-agb",
    "/usr/share/doc/unix-agb/egress-guardian.json.example",
    "/run/unix-agb",
    "/run/unix-agb/guardian.sock",
    "/run/unix-agb/control.sock",
    "/var/lib/unix-agb",
    "/var/lib/unix-agb/egress-guardian-state.json",
    "/var/lib/unix-agb/egress-enforcement.jsonl",
    "/var/lib/unix-agb/gate3-cache.json",
    "/etc/systemd/system/multi-user.target.wants/unix-agb-egress-guardian.service",
)


def command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=False)


def account_exists(database: str, name: str) -> bool:
    try:
        (pwd.getpwnam if database == "passwd" else grp.getgrnam)(name)
        return True
    except KeyError:
        return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    package = command("dpkg-query", "-W", "-f=${db:Status-Abbrev}", PACKAGE)
    unit_files = command("systemctl", "list-unit-files", UNIT, "--no-legend", "--no-pager")
    active = command("systemctl", "is-active", UNIT)
    processes = [line for line in command("ps", "-eo", "pid=,args=").stdout.splitlines() if "agb-egress-guardian" in line and "audit_gate4_package_cleanup" not in line]
    unix_sockets = [line for line in Path("/proc/net/unix").read_text().splitlines() if "unix-agb" in line]
    cgroups = [str(Path(root) / name) for root, directories, _files in os.walk("/sys/fs/cgroup") for name in directories if "unix-agb" in name]
    existing_paths = [path for path in PATHS if Path(path).exists() or Path(path).is_symlink()]
    report = {
        "proof": "unix-agb-gate4-package-cleanup-v1",
        "package": {"present_in_dpkg": package.returncode == 0, "query": package.stdout.strip()},
        "unit": {"unit_file_present": bool(unit_files.stdout.strip()), "active": active.stdout.strip() == "active"},
        "accounts": {"user_present": account_exists("passwd", "unix-agb-guardian"), "group_present": account_exists("group", "unix-agb-guardian")},
        "processes": processes,
        "unix_sockets": unix_sockets,
        "cgroups": cgroups,
        "existing_paths": existing_paths,
    }
    report["criteria"] = {
        "package_absent": not report["package"]["present_in_dpkg"],
        "unit_absent": not report["unit"]["unit_file_present"] and not report["unit"]["active"],
        "accounts_absent": not any(report["accounts"].values()),
        "processes_absent": not processes,
        "listeners_absent": not unix_sockets,
        "cgroups_absent": not cgroups,
        "paths_absent": not existing_paths,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    if not all(report["criteria"].values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
