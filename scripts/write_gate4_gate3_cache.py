#!/usr/bin/env python3
"""Write an authenticated controlled Gate 3 cache fixture atomically."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import time
from pathlib import Path


REVISION = "policy:bpf-observer-v1"


def snapshot(
    namespace: str | None,
    secret: bytes,
    expires_epoch: int,
    revision: str = REVISION,
) -> dict[str, object]:
    entries = []
    if namespace is not None:
        resource = hashlib.sha256(b"controlled-trajectory-egress-containment").hexdigest()
        evidence = hashlib.sha256(f"controlled:{namespace}".encode()).hexdigest()
        entries.append({
            "cache_key": f"{namespace}|network.connect|{resource}",
            "decision_id": "dec:" + hashlib.sha256(f"{namespace}\0{expires_epoch}".encode()).hexdigest(),
            "namespace_id": namespace,
            "operation": "network.connect",
            "resource_sha256": resource,
            "effect": "DENY",
            "policy_revision": revision,
            "state_revision": 1,
            "evidence_sha256": evidence,
            "expires_epoch": expires_epoch,
        })
    payload = json.dumps([1, revision, entries], separators=(",", ":")).encode()
    return {
        "format_version": 1,
        "policy_revision": revision,
        "entries": entries,
        "hmac_sha256": hmac.new(secret, payload, hashlib.sha256).hexdigest(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--namespace")
    parser.add_argument("--policy-revision", default=REVISION)
    parser.add_argument("--ttl-seconds", type=int, default=30)
    args = parser.parse_args()
    secret = args.key.read_bytes().strip()
    if len(secret) < 32:
        parser.error("cache key must contain at least 32 bytes")
    if not 1 <= args.ttl_seconds <= 3600:
        parser.error("TTL must be between 1 and 3600 seconds")
    document = snapshot(
        args.namespace,
        secret,
        int(time.time()) + args.ttl_seconds,
        args.policy_revision,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.{os.getpid()}.tmp")
    with temporary.open("w") as stream:
        json.dump(document, stream, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o640)
    os.replace(temporary, args.output)
    directory = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


if __name__ == "__main__":
    main()
