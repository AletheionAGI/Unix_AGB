#!/usr/bin/env python3
"""Run the admin UID/GID matrix with a temporary real Linux account.

Account creation is intentionally opt-in (AGB_RUN_PRIVILEGED_IDENTITY_TEST=1)
and requires root. This prevents accidental mutation of development hosts.
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import subprocess
import tempfile
from pathlib import Path


def main() -> None:
    if os.geteuid() != 0 or os.getenv("AGB_RUN_PRIVILEGED_IDENTITY_TEST") != "1":
        print(json.dumps({"status": "skipped", "reason": "requires root and AGB_RUN_PRIVILEGED_IDENTITY_TEST=1"}, indent=2))
        return
    if not shutil.which("useradd") or not shutil.which("userdel"):
        raise SystemExit("useradd/userdel are required")
    name = f"agbtest-{os.getpid()}"
    subprocess.run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name], check=True)
    try:
        account = pwd.getpwnam(name)
        root = Path(__file__).resolve().parents[1]
        binary = root / "target/debug/agb-admin-server"
        if not binary.exists():
            subprocess.run(["cargo", "build", "--quiet", "--bin", "agb-admin-server"], cwd=root, check=True)
        with tempfile.TemporaryDirectory(prefix="agb-privileged-identity-") as directory:
            base = Path(directory)
            lab_binary = base / "agb-admin-server"
            import shutil as _shutil
            _shutil.copy2(binary, lab_binary)
            lab_binary.chmod(0o755)
            env = {**os.environ, "AGB_ADMIN_TOKEN": "lab-token", "AGB_ADMIN_UIDS": str(account.pw_uid), "AGB_ADMIN_GIDS": str(account.pw_gid)}
            command = ["runuser", "-u", name, "--", str(lab_binary), str(base / "admin.sock"), str(base / "cache"), str(base / "audit")]
            process = subprocess.Popen(command, env=env)
            try:
                subprocess.run(["python3", str(root / "scripts/test_admin_uid_gid_matrix.py")], cwd=root, env=env, check=True)
                audit = base / "audit"
                print(json.dumps({"status": "passed", "uid": account.pw_uid, "gid": account.pw_gid, "audit_exists": audit.exists()}, indent=2))
            finally:
                process.terminate()
                process.wait(timeout=5)
    finally:
        subprocess.run(["userdel", name], check=True)


if __name__ == "__main__":
    main()
