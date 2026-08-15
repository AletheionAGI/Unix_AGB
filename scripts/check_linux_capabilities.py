#!/usr/bin/env python3
"""Report host capabilities needed by the next Unix-AGB prototype gate."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def main() -> None:
    tracefs = Path("/sys/kernel/tracing")
    print(f"kernel={os.uname().release}")
    print(f"bpftrace={shutil.which('bpftrace') or 'missing'}")
    print(f"bpftool={shutil.which('bpftool') or 'missing'}")
    print(f"auditctl={shutil.which('auditctl') or 'missing'}")
    print(f"tracefs={'present' if tracefs.is_dir() else 'missing'}")
    print(f"landlock={'present' if Path('/sys/kernel/security/landlock').exists() else 'unknown'}")
    print("observer=bpftrace script available; privilege check occurs at execution")
    print("external_enforcement=seccomp-user-notify adapter not implemented")


if __name__ == "__main__":
    main()

