"""Decision ensemble with explicit disagreement handling and telemetry."""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Protocol


class DecisionEngine(Protocol):
    name: str

    def update(self, event: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class EnsemblePolicy:
    deny_votes_required: int = 2
    disagreement_action: str = "abstain"

    def __post_init__(self) -> None:
        if self.disagreement_action not in {"abstain", "majority"}:
            raise ValueError("disagreement_action must be 'abstain' or 'majority'")


class DecisionEnsemble:
    """Combine member decisions and retain disagreement as first-class telemetry.

    ``abstain`` is the operational default: a split vote is never compiled into
    model-derived enforcement. ``majority`` is an explicit opt-in matching the
    frozen Gate 2B v5 2-of-3 experiment.
    """

    name = "D:asm-cm-ensemble"

    def __init__(
        self, engines: Iterable[DecisionEngine], *, policy: EnsemblePolicy | None = None
    ) -> None:
        self.engines = tuple(engines)
        self.policy = policy or EnsemblePolicy()
        if not self.engines:
            raise ValueError("ensemble requires at least one member")
        if not 1 <= self.policy.deny_votes_required <= len(self.engines):
            raise ValueError("deny_votes_required must fit ensemble member count")
        names = [engine.name for engine in self.engines]
        if len(set(names)) != len(names):
            raise ValueError("ensemble member names must be unique")
        self._events = 0
        self._disagreements = 0
        self._effects: Counter[str] = Counter()
        self._member_inferences: Counter[str] = Counter()

    @property
    def telemetry(self) -> dict[str, Any]:
        return {
            "events": self._events,
            "disagreements": self._disagreements,
            "disagreement_rate": self._disagreements / self._events if self._events else 0.0,
            "effects": dict(sorted(self._effects.items())),
            "member_inference_counts": {
                engine.name: self._member_inferences[engine.name]
                for engine in self.engines
            },
            "total_member_inferences": sum(self._member_inferences.values()),
            "policy": {
                "deny_votes_required": self.policy.deny_votes_required,
                "disagreement_action": self.policy.disagreement_action,
            },
        }

    def synchronize(self) -> None:
        for engine in self.engines:
            synchronize = getattr(engine, "synchronize", None)
            if synchronize:
                synchronize()

    def reset_peak_memory_stats(self) -> None:
        # CUDA peak accounting is process/device global; one reset is sufficient.
        reset = getattr(self.engines[0], "reset_peak_memory_stats", None)
        if reset:
            reset()

    def accelerator_memory(self) -> dict[str, int] | None:
        memory = getattr(self.engines[0], "accelerator_memory", None)
        return memory() if memory else None

    def update(self, event: dict[str, Any]) -> dict[str, Any]:
        results = [engine.update(event) for engine in self.engines]
        for engine, result in zip(self.engines, results):
            self._member_inferences[engine.name] += int(
                bool(result.get("model_inference_performed"))
            )
        revisions = {int(result["state_revision"]) for result in results}
        if len(revisions) != 1:
            raise RuntimeError("ensemble members returned different state revisions")
        effects = [str(result.get("effect", "ABSTAIN")) for result in results]
        if any(effect not in {"ALLOW", "DENY", "ABSTAIN"} for effect in effects):
            raise RuntimeError("ensemble member returned an invalid effect")
        disagreement = len(set(effects)) > 1
        deny_votes = effects.count("DENY")
        majority_effect = "DENY" if deny_votes >= self.policy.deny_votes_required else "ALLOW"
        member_abstained = "ABSTAIN" in effects
        effect = "ABSTAIN" if member_abstained else majority_effect
        if disagreement and self.policy.disagreement_action == "abstain":
            effect = "ABSTAIN"
        evidence_ids = list(
            dict.fromkeys(
                evidence
                for result in results
                for evidence in result.get("evidence_ids", [])
            )
        )
        confidences = [
            float(result["confidence"])
            for result in results
            if result.get("confidence") is not None
        ]
        fingerprints = [result.get("checkpoint_fingerprint") for result in results]
        aggregate_fingerprint = None
        if all(isinstance(value, str) and value for value in fingerprints):
            aggregate_fingerprint = hashlib.sha256(
                "\n".join(fingerprints).encode()
            ).hexdigest()
        self._events += 1
        self._disagreements += int(disagreement)
        self._effects[effect] += 1
        return {
            "engine": self.name,
            "namespace_id": event["namespace_id"],
            "event_id": event["event_id"],
            "effect": effect,
            "reason": (
                "ENSEMBLE_MEMBER_ABSTAINED"
                if member_abstained
                else "ENSEMBLE_DISAGREEMENT"
                if disagreement
                else "ENSEMBLE_UNANIMOUS"
            ),
            "evidence_ids": evidence_ids or [event["event_id"]],
            "confidence": min(confidences) if confidences else None,
            "state_revision": revisions.pop(),
            "checkpoint_fingerprint": aggregate_fingerprint,
            "checkpoint_fingerprints": fingerprints,
            "model_inference_performed": any(
                result.get("model_inference_performed", False) for result in results
            ),
            "ensemble": {
                "member_effects": effects,
                "deny_votes": deny_votes,
                "deny_votes_required": self.policy.deny_votes_required,
                "disagreement": disagreement,
                "member_abstained": member_abstained,
                "disagreement_action": self.policy.disagreement_action,
                "majority_effect": majority_effect,
            },
        }
