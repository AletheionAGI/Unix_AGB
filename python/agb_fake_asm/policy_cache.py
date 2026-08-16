"""Versioned decision cache for the deterministic enforcement edge."""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any


@dataclass(frozen=True)
class CacheEntry:
    effect: str
    policy_revision: str
    expires_at: float


class DecisionCache:
    """Fail-closed cache: misses never invent an ALLOW decision."""

    def __init__(self, ttl_seconds: float = 2.0) -> None:
        self.ttl_seconds = ttl_seconds
        self._entries: dict[tuple[Any, ...], CacheEntry] = {}

    def put(self, key: tuple[Any, ...], effect: str, policy_revision: str) -> None:
        if effect not in {"ALLOW", "DENY", "ABSTAIN"}:
            raise ValueError(f"unsupported effect: {effect}")
        self._entries[key] = CacheEntry(effect, policy_revision, time.monotonic() + self.ttl_seconds)

    def get(self, key: tuple[Any, ...], policy_revision: str) -> str | None:
        entry = self._entries.get(key)
        if entry is None or entry.policy_revision != policy_revision:
            return None
        if entry.expires_at <= time.monotonic():
            self._entries.pop(key, None)
            return None
        return entry.effect

    def clear(self) -> None:
        self._entries.clear()
