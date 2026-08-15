"""Small, deterministic state engine implementing the Gate 0 contract."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class _NamespaceState:
    revision: int = 0
    saw_exec: bool = False
    saw_network_after_exec: bool = False
    exec_event_id: str | None = None
    network_event_id: str | None = None


class FakeAsmEngine:
    """Translate synthetic events into isolated state summaries.

    This is test plumbing, not a detection model. State is keyed by the stable
    namespace identifier supplied by the gateway, never by PID alone.
    """

    def __init__(self) -> None:
        self._namespaces: dict[str, _NamespaceState] = {}

    @property
    def namespace_count(self) -> int:
        return len(self._namespaces)

    def update(self, event: dict[str, Any]) -> dict[str, Any]:
        namespace_id = event["namespace_id"]
        state = self._namespaces.setdefault(namespace_id, _NamespaceState())
        state.revision += 1

        operation = event["operation"]
        if operation == "process.exec":
            state.saw_exec = True
            state.exec_event_id = event["event_id"]
        if operation == "network.connect" and state.saw_exec:
            state.saw_network_after_exec = True
            state.network_event_id = event["event_id"]

        sensitive_access = (
            operation == "file.open" and "credential" in event.get("labels", [])
        )
        elevated = state.saw_network_after_exec and sensitive_access

        signals: list[str] = []
        if state.saw_exec:
            signals.append("exec_observed")
        if state.saw_network_after_exec:
            signals.append("network_after_exec")
        if sensitive_access:
            signals.append("credential_access")
        if elevated:
            signals.append("exec_network_credential_chain")

        evidence_ids = [
            event_id
            for event_id in (state.exec_event_id, state.network_event_id)
            if event_id is not None
        ]
        if event["event_id"] not in evidence_ids:
            evidence_ids.append(event["event_id"])

        return {
            "schema_version": "1.0",
            "namespace_id": namespace_id,
            "state_revision": state.revision,
            "risk_band": "elevated" if elevated else "normal",
            "confidence": None,
            "signals": signals,
            "evidence_ids": evidence_ids,
            "engine": "fake",
            "checkpoint_fingerprint": None,
            "updated_at": event["occurred_at"],
        }
