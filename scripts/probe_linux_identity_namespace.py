#!/usr/bin/env python3
"""Probe Linux UID/GID and user-namespace behavior without persistent changes."""

from __future__ import annotations

import json
import os
import shutil
import subprocess


def main() -> None:
    report: dict[str, object] = {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "unshare": shutil.which("unshare"),
        "user_namespace": "not-tested",
    }
    if report["unshare"]:
        result = subprocess.run(
            ["unshare", "-Ur", "sh", "-c", "printf '%s:%s\n' \"$(id -u)\" \"$(id -g)\""],
            capture_output=True,
            text=True,
            check=False,
        )
        report["user_namespace"] = "supported" if result.returncode == 0 else "blocked"
        report["namespace_identity"] = result.stdout.strip() if result.returncode == 0 else result.stderr.strip()
    print(json.dumps(report, indent=2))
    if report["user_namespace"] == "blocked":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
