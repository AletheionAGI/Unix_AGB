#!/usr/bin/env python3
"""Protocol health check for the Rust policy broker Unix socket."""

from __future__ import annotations

import argparse
import json
import socket
import sys


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default="var/agb-policy.sock")
    args = parser.parse_args()
    request = {
        "namespace_id": "health:probe",
        "resource": "health://broker",
        "policy_revision": "policy:health-probe",
        "requested_effect": "ALLOW",
    }
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2.0)
            client.connect(args.socket)
            client.sendall((json.dumps(request) + "\n").encode())
            response = json.loads(client.makefile("rb").readline())
        required = {"schema_version", "effect", "backend", "policy_revision", "fallback"}
        missing = required.difference(response)
        if missing or response["backend"] != "seccomp-user-notify":
            raise RuntimeError(f"invalid health response: missing={sorted(missing)}")
        print(json.dumps({"healthy": True, "backend": response["backend"], "effect": response["effect"]}))
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"healthy": False, "error": str(error)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
