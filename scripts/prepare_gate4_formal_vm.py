#!/usr/bin/env python3
"""Install and activate the frozen Gate 4 package only in a disposable Ubuntu VM."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import platform
import pwd
import grp
import subprocess
from pathlib import Path

EXPECTED_SHA256 = "a14a3d342da5ba6b2ca5c49824784d99f6d414afcd3b5dc2b4fc556d784b0c00"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", type=Path, default=Path("var/package/unix-agb-egress-guardian-lab_0.3.1_all.deb"))
    parser.add_argument("--apply", action="store_true", help="acknowledge VM-local package and service changes")
    args = parser.parse_args()
    release = platform.freedesktop_os_release()
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") not in {"24.04", "26.04"}:
        raise SystemExit("preparation is restricted to preregistered Ubuntu releases")
    if subprocess.run(["systemd-detect-virt", "--quiet", "--vm"], check=False).returncode != 0:
        raise SystemExit("refusing activation outside a detected virtual machine")
    if os.geteuid() != 0:
        raise SystemExit("run this preparer with sudo inside the disposable VM")
    if not args.apply:
        raise SystemExit("no changes made; pass --apply to acknowledge installation and activation")
    if not args.package.is_file() or hashlib.sha256(args.package.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise SystemExit("frozen package is missing or has the wrong SHA-256")
    subprocess.run(["dpkg", "-i", str(args.package.resolve())], check=True)
    config_path = Path("/etc/unix-agb/egress-guardian.json")
    config = json.loads(config_path.read_text())
    config["enabled"] = True
    config["gate3_policy_revision"] = "policy:bpf-observer-v2"
    temporary = config_path.with_name(".egress-guardian.json.gate4-formal.tmp")
    temporary.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n")
    os.chmod(temporary, 0o644); os.replace(temporary, config_path)
    revision = "policy:bpf-observer-v2"
    secret = Path(config["gate3_cache_key"]).read_bytes().strip()
    payload = json.dumps([1, revision, []], separators=(",", ":")).encode()
    cache = {"format_version": 1, "policy_revision": revision, "entries": [],
             "hmac_sha256": hmac.new(secret, payload, hashlib.sha256).hexdigest()}
    cache_path = Path(config["gate3_cache"]); cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_temporary = cache_path.with_name(".gate3-cache.json.gate4-formal.tmp")
    cache_temporary.write_text(json.dumps(cache, separators=(",", ":")) + "\n")
    os.chmod(cache_temporary, 0o640)
    os.chown(cache_temporary, pwd.getpwnam("unix-agb-guardian").pw_uid,
             grp.getgrnam("unix-agb-guardian").gr_gid)
    os.replace(cache_temporary, cache_path)
    Path("/etc/unix-agb/egress-guardian.enabled").touch(mode=0o600, exist_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "unix-agb-egress-guardian.service"], check=True)
    subprocess.run(["systemctl", "is-active", "--quiet", "unix-agb-egress-guardian.service"], check=True)
    print(json.dumps({"prepared": True, "ubuntu_release": release["VERSION_ID"],
                      "artifact_sha256": EXPECTED_SHA256,
                      "policy_revision": "policy:bpf-observer-v2"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
