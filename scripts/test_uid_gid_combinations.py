#!/usr/bin/env python3
"""Document and probe simultaneous UID/GID allowlist combinations."""
import json
import os

print(json.dumps({
    "status": "ready",
    "host_uid": os.getuid(),
    "host_gid": os.getgid(),
    "cases": [
        {"name": "uid_and_gid", "expected": "accept only matching pair"},
        {"name": "shared_gid", "expected": "group rule may accept distinct UID"},
        {"name": "uid_only", "expected": "accept matching UID regardless of GID"},
    ],
    "note": "run privileged-identity harness on a lab host with a shared supplemental group",
}, indent=2))
