"""Frozen Gate 2 baselines and a replaceable state-engine boundary."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Any

Event = dict[str, Any]


class BenchmarkEngine(ABC):
    name: str

    @abstractmethod
    def update(self, event: Event) -> dict[str, Any]:
        """Consume one event and return an auditable decision."""


def _decision(engine: str, event: Event, deny: bool, evidence: list[str]) -> dict[str, Any]:
    return {
        "engine": engine,
        "namespace_id": event["namespace_id"],
        "event_id": event["event_id"],
        "effect": "DENY" if deny else "ALLOW",
        "evidence_ids": evidence,
    }


class EventLocalEngine(BenchmarkEngine):
    name = "A:event-local"

    def update(self, event: Event) -> dict[str, Any]:
        sensitive = event["operation"] == "file.open" and "credential" in event.get("labels", [])
        return _decision(self.name, event, sensitive, [event["event_id"]])


@dataclass
class _SequenceState:
    saw_exec: bool = False
    network_event_id: str | None = None


class SequenceRuleEngine(BenchmarkEngine):
    name = "B:sequence-rule"

    def __init__(self) -> None:
        self._states: dict[str, _SequenceState] = {}

    def update(self, event: Event) -> dict[str, Any]:
        state = self._states.setdefault(event["namespace_id"], _SequenceState())
        if event["operation"] == "process.exec":
            state.saw_exec = True
            state.network_event_id = None
        if event["operation"] == "identity.change" and "trusted-reset" in event.get("labels", []):
            state.network_event_id = None
        if (
            event["operation"] == "network.connect"
            and state.saw_exec
            and "trusted-network" not in event.get("labels", [])
        ):
            state.network_event_id = event["event_id"]
        sensitive = event["operation"] == "file.open" and "credential" in event.get("labels", [])
        deny = sensitive and state.network_event_id is not None
        evidence = [state.network_event_id, event["event_id"]] if deny else [event["event_id"]]
        return _decision(self.name, event, deny, [item for item in evidence if item])


@dataclass
class _WindowState:
    recent: deque[tuple[str, str]] = field(default_factory=deque)


class SlidingWindowEngine(BenchmarkEngine):
    name = "C:sliding-window"

    def __init__(self, window_events: int = 3) -> None:
        self.window_events = window_events
        self._states: dict[str, _WindowState] = {}

    def update(self, event: Event) -> dict[str, Any]:
        state = self._states.setdefault(event["namespace_id"], _WindowState())
        if event["operation"] == "identity.change" and "trusted-reset" in event.get("labels", []):
            state.recent.clear()
        operation = event["operation"]
        if operation == "network.connect" and "trusted-network" in event.get("labels", []):
            operation = "network.trusted"
        state.recent.append((operation, event["event_id"]))
        while len(state.recent) > self.window_events:
            state.recent.popleft()
        sensitive = event["operation"] == "file.open" and "credential" in event.get("labels", [])
        network_ids = [
            event_id
            for operation, event_id in state.recent
            if operation == "network.connect"
        ]
        deny = sensitive and bool(network_ids)
        evidence = [network_ids[-1], event["event_id"]] if deny else [event["event_id"]]
        return _decision(self.name, event, deny, evidence)


@dataclass
class _ProxyState:
    revision: int = 0
    last_sequence: int = 0
    saw_exec: bool = False
    network_event_id: str | None = None


class StatefulProxyEngine(BenchmarkEngine):
    """Deterministic Gate 2 seam; this is not a learned ASM-CM model."""

    name = "D:stateful-proxy"

    def __init__(self) -> None:
        self.states: dict[str, _ProxyState] = {}

    def update(self, event: Event) -> dict[str, Any]:
        state = self.states.setdefault(event["namespace_id"], _ProxyState())
        sequence = int(event["sequence"])
        if sequence != state.last_sequence + 1:
            return {
                **_decision(self.name, event, False, [event["event_id"]]),
                "effect": "ABSTAIN",
                "reason": "SEQUENCE_GAP",
                "state_revision": state.revision,
            }
        state.last_sequence = sequence
        state.revision += 1
        if event["operation"] == "process.exec":
            state.saw_exec = True
            state.network_event_id = None
        if event["operation"] == "identity.change" and "trusted-reset" in event.get("labels", []):
            state.network_event_id = None
        if (
            event["operation"] == "network.connect"
            and state.saw_exec
            and "trusted-network" not in event.get("labels", [])
        ):
            state.network_event_id = event["event_id"]
        sensitive = event["operation"] == "file.open" and "credential" in event.get("labels", [])
        deny = sensitive and state.network_event_id is not None
        evidence = [state.network_event_id, event["event_id"]] if deny else [event["event_id"]]
        return {
            **_decision(self.name, event, deny, [item for item in evidence if item]),
            "state_revision": state.revision,
        }
