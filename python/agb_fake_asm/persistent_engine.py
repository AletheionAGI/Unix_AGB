"""Atomic, fail-closed snapshots for the Gate 2 stateful proxy."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import copy
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .benchmark_engines import StatefulProxyEngine, _ProxyState

FORMAT_VERSION = 1
ENGINE_FINGERPRINT = "sha256:stateful-proxy-v1"


class SnapshotError(RuntimeError):
    pass


class PersistentStatefulProxy(StatefulProxyEngine):
    def __init__(self, path: Path, configuration_fingerprint: str) -> None:
        super().__init__()
        self.path = path
        self.configuration_fingerprint = configuration_fingerprint
        if path.exists():
            self._restore()

    @staticmethod
    def _checksum(payload: dict[str, Any]) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def _restore(self) -> None:
        try:
            document = json.loads(self.path.read_text())
            checksum = document.pop("checksum")
            if checksum != self._checksum(document):
                raise SnapshotError("snapshot checksum mismatch")
            if document["format_version"] != FORMAT_VERSION:
                raise SnapshotError("unsupported snapshot format")
            if document["engine_fingerprint"] != ENGINE_FINGERPRINT:
                raise SnapshotError("engine fingerprint mismatch")
            if document["configuration_fingerprint"] != self.configuration_fingerprint:
                raise SnapshotError("configuration fingerprint mismatch")
            self.states = {
                namespace: _ProxyState(**state)
                for namespace, state in document["namespaces"].items()
            }
        except SnapshotError:
            raise
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise SnapshotError(f"invalid snapshot: {error}") from error

    def checkpoint(self) -> None:
        document: dict[str, Any] = {
            "format_version": FORMAT_VERSION,
            "engine_fingerprint": ENGINE_FINGERPRINT,
            "configuration_fingerprint": self.configuration_fingerprint,
            "namespaces": {
                namespace: asdict(state) for namespace, state in sorted(self.states.items())
            },
        }
        document["checksum"] = self._checksum(document)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w") as output:
                json.dump(document, output, sort_keys=True, separators=(",", ":"))
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def update(self, event: dict[str, Any]) -> dict[str, Any]:
        previous = copy.deepcopy(self.states)
        decision = super().update(event)
        if decision["effect"] != "ABSTAIN":
            try:
                self.checkpoint()
            except Exception:
                self.states = previous
                raise
        return decision
