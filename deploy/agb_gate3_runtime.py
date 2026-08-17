"""Authenticated Gate 3 cache projection for the Gate 4 service guardian."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
from pathlib import Path
from typing import Any


ENTRY_FIELDS = (
    "cache_key", "decision_id", "namespace_id", "operation", "resource_sha256",
    "effect", "policy_revision", "state_revision", "evidence_sha256", "expires_epoch",
)


class Gate3CacheError(ValueError):
    pass


def authenticated_entries(payload: bytes, secret: bytes, revision: str) -> list[dict[str, Any]]:
    try:
        snapshot = json.loads(payload)
        if set(snapshot) != {"format_version", "policy_revision", "entries", "hmac_sha256"}:
            raise Gate3CacheError("CACHE_FIELDS_INVALID")
        if snapshot["format_version"] != 1:
            raise Gate3CacheError("CACHE_FORMAT_UNSUPPORTED")
        if snapshot["policy_revision"] != revision:
            raise Gate3CacheError("CACHE_REVISION_MISMATCH")
        entries = [{field: item[field] for field in ENTRY_FIELDS} for item in snapshot["entries"]]
        encoded = json.dumps([1, revision, entries], separators=(",", ":")).encode()
        expected = hmac.new(secret, encoded, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(snapshot["hmac_sha256"]), expected):
            raise Gate3CacheError("CACHE_AUTHENTICATION_FAILED")
    except Gate3CacheError:
        raise
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise Gate3CacheError("CACHE_INVALID") from error
    for item in entries:
        if (
            item["effect"] != "DENY"
            or item["policy_revision"] != revision
            or not isinstance(item["expires_epoch"], int)
            or item["state_revision"] < 1
        ):
            raise Gate3CacheError("CACHE_DECISION_INVALID")
    return entries


class Gate3RuntimePolicy:
    """Retain the last authenticated snapshot and never accept partial reloads."""

    def __init__(self, cache_path: Path, key_path: Path, revision: str) -> None:
        self.cache_path = cache_path
        self.key_path = key_path
        self.revision = revision
        self._lock = threading.Lock()
        self._reload_lock = threading.Lock()
        self._fingerprint: tuple[int, int] | None = None
        self._entries: list[dict[str, Any]] | None = None
        self.last_reload_reason = "NOT_LOADED"

    def reload(self, *, required: bool = False) -> bool:
        with self._reload_lock:
            try:
                stat = self.cache_path.stat()
                fingerprint = (stat.st_mtime_ns, stat.st_size)
                if fingerprint == self._fingerprint and self._entries is not None:
                    return False
                secret = self.key_path.read_bytes().strip()
                if len(secret) < 32:
                    raise Gate3CacheError("CACHE_KEY_INVALID")
                entries = authenticated_entries(self.cache_path.read_bytes(), secret, self.revision)
            except (OSError, Gate3CacheError) as error:
                self.last_reload_reason = str(error)
                if required or self._entries is None:
                    raise Gate3CacheError(self.last_reload_reason) from error
                return False
            with self._lock:
                self._entries = entries
                self._fingerprint = fingerprint
                self.last_reload_reason = "CACHE_AUTHENTICATED"
            return True

    def decide(self, namespace_id: str, now_epoch: int | None = None) -> tuple[bool, str, str | None]:
        self.reload(required=self._entries is None)
        now = int(time.time()) if now_epoch is None else now_epoch
        with self._lock:
            entries = list(self._entries or [])
        decisions = [
            item for item in entries
            if item["namespace_id"] == namespace_id
            and item["expires_epoch"] > now
        ]
        if not decisions:
            return False, "NO_ACTIVE_GATE3_DENY", None
        newest = max(decisions, key=lambda item: (item["state_revision"], item["expires_epoch"]))
        return True, f"ACTIVE_GATE3_TRAJECTORY_DENY:{newest['operation']}", str(newest["decision_id"])
