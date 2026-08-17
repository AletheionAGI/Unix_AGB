#!/usr/bin/env python3
"""Build the reversible Gate 4 lifecycle laboratory Debian package."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.0"
PACKAGE = "unix-agb-egress-guardian-lab"


def write(path: Path, content: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)


def copy(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "var/package")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / f"{PACKAGE}_{VERSION}_all.deb"

    with tempfile.TemporaryDirectory(prefix="unix-agb-deb-") as directory:
        tree = Path(directory) / PACKAGE
        control = tree / "DEBIAN"
        control.mkdir(parents=True)
        write(control / "control", f"""Package: {PACKAGE}
Version: {VERSION}
Section: admin
Priority: optional
Architecture: all
Depends: python3, adduser, systemd, libseccomp2
Maintainer: Unix-AGB laboratory <noreply@example.invalid>
Description: Unix-AGB Gate 4 reversible lifecycle laboratory
 Boot-persistent health and rollback validation only. This package does not
 claim persistent seccomp enforcement readiness.
""")
        write(control / "conffiles", "/etc/unix-agb/egress-guardian.json\n")
        write(control / "postinst", """#!/bin/sh
set -eu
if ! getent group unix-agb-guardian >/dev/null; then
  addgroup --system unix-agb-guardian
fi
if ! getent passwd unix-agb-guardian >/dev/null; then
  adduser --system --ingroup unix-agb-guardian --home /nonexistent --no-create-home --shell /usr/sbin/nologin unix-agb-guardian
fi
if [ ! -e /etc/unix-agb/handoff.key ]; then
  umask 027
  head -c 32 /dev/urandom | base64 > /etc/unix-agb/handoff.key
fi
chown root:unix-agb-guardian /etc/unix-agb/handoff.key
chmod 0640 /etc/unix-agb/handoff.key
systemctl daemon-reload >/dev/null 2>&1 || true
exit 0
""", 0o755)
        write(control / "prerm", """#!/bin/sh
set -eu
if [ "$1" = remove ] || [ "$1" = deconfigure ]; then
  systemctl disable --now unix-agb-egress-guardian.service >/dev/null 2>&1 || true
fi
exit 0
""", 0o755)
        write(control / "postrm", """#!/bin/sh
set -eu
systemctl daemon-reload >/dev/null 2>&1 || true
if [ "$1" = purge ]; then
  rm -f /etc/unix-agb/egress-guardian.enabled
  rm -f /etc/unix-agb/handoff.key
  rm -f /run/unix-agb/guardian.sock
  rm -f /run/unix-agb/control.sock
  rm -f /var/lib/unix-agb/egress-guardian-state.json
  rm -f /var/lib/unix-agb/egress-enforcement.jsonl
  if getent passwd unix-agb-guardian >/dev/null; then
    deluser --system unix-agb-guardian >/dev/null 2>&1 || true
  fi
  if getent group unix-agb-guardian >/dev/null; then
    delgroup --system unix-agb-guardian >/dev/null 2>&1 || true
  fi
  rmdir /etc/unix-agb /run/unix-agb /var/lib/unix-agb 2>/dev/null || true
fi
exit 0
""", 0o755)

        copy(ROOT / "deploy/agb-egress-guardian", tree / "usr/libexec/unix-agb/agb-egress-guardian", 0o755)
        copy(ROOT / "deploy/agb-egress-launch", tree / "usr/libexec/unix-agb/agb-egress-launch", 0o755)
        copy(ROOT / "deploy/unix-agb-egress-guardian.service", tree / "usr/lib/systemd/system/unix-agb-egress-guardian.service", 0o644)
        copy(ROOT / "deploy/egress-guardian.json.example", tree / "usr/share/doc/unix-agb/egress-guardian.json.example", 0o644)
        write(tree / "etc/unix-agb/egress-guardian.json", """{
  "enabled": false,
  "mode": "laboratory-exact-launch",
  "policy_revision": "policy:gate4-egress-guardian-v2",
  "handoff_key": "/etc/unix-agb/handoff.key",
  "protected_cgroup": null
}
""")
        environment = {**os.environ, "SOURCE_DATE_EPOCH": "1786924800"}
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(tree), str(output)], check=True, env=environment)
    print(output)


if __name__ == "__main__":
    main()
