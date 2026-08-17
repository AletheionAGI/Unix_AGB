"""Reusable, label-independent entity canonicalization for model inputs."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class CanonicalEntityEncoder:
    """Assign trajectory-local entity tokens in first-occurrence order.

    Control and relation tokens below ``entity_token_start`` pass through
    unchanged. The encoder owns one trajectory mapping and is intentionally
    reset between trajectories.
    """

    entity_token_start: int = 32
    token_limit: int = 256
    _mapping: dict[int, int] = field(default_factory=dict, init=False)

    def encode(self, tokens: Iterable[int]) -> list[int]:
        encoded: list[int] = []
        for token in tokens:
            if not isinstance(token, int) or isinstance(token, bool):
                raise TypeError("model tokens must be integers")
            if token < 0:
                raise ValueError("model tokens must be non-negative")
            if token < self.entity_token_start:
                encoded.append(token)
                continue
            if token not in self._mapping:
                canonical = self.entity_token_start + len(self._mapping)
                if canonical >= self.token_limit:
                    raise ValueError("trajectory exceeds canonical entity-token budget")
                self._mapping[token] = canonical
            encoded.append(self._mapping[token])
        return encoded


def canonicalize_trajectory(item: dict[str, Any]) -> dict[str, Any]:
    """Return a deep-copied trajectory with only its token input rewritten."""
    result = copy.deepcopy(item)
    tokens = result.get("tokens")
    if not isinstance(tokens, list):
        raise ValueError("trajectory tokens must be a list")
    result["tokens"] = CanonicalEntityEncoder().encode(tokens)
    return result


def canonicalize_trajectories(items: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Canonicalize each trajectory independently without inspecting labels."""
    return [canonicalize_trajectory(item) for item in items]
