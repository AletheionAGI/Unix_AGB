#!/usr/bin/env python3
"""Exercise admin authorization with real Linux account/group identities.

The probe is deliberately non-destructive: it uses an existing ``nobody``
account when the host permits switching identities and otherwise records a
skip. Creating or deleting host accounts is left to an explicit lab harness.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
from pathlib import Path


def main() -> None:
    nobody = pwd.getpwnam("nobody") if _exists("nobody") else None
    result: dict[str, object] = {
        "host_uid": os.getuid(),
        "host_gid": os.getgid(),
        "dedicated_account": None,
        "status": "skipped",
        "reason": "nobody account or identity-switch tool unavailable",
        "tools": {name: bool(shutil.which(name)) for name in ("runuser", "setpriv")},
    }
    if nobody is not None:
        result["dedicated_account"] = {
            "name": nobody.pw_name,
            "uid": nobody.pw_uid,
            "gid": nobody.pw_gid,
            "group": grp.getgrgid(nobody.pw_gid).gr_name,
        }
        if os.geteuid() == 0 and (shutil.which("runuser") or shutil.which("setpriv")):
            result["status"] = "ready"
            result["reason"] = "existing account can be exercised by a privileged lab harness"
        else:
            result["reason"] = "identity switching requires root; no host accounts were modified"
    print(json.dumps(result, indent=2, sort_keys=True))


def _exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
    except KeyError:
        return False
    return True


if __name__ == "__main__":
    main()
