"""Real ASM-CM adapter for Unix-AGB security trajectories.

ASM-CM selects canonical evidence identifiers. A deterministic policy remains
authoritative for ALLOW/DENY and never treats neural output as historical truth.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import sys
import tempfile
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

NETWORK_RELATION_KEY = 2
PERSISTENCE_RELATION_KEY = 3
ADMIN_RELATION_KEY = 4
VALUE_OFFSET = 34
VALUE_CAPACITY = 64
MAX_CAUSAL_TOKEN_HISTORY = VALUE_CAPACITY * 2
FILLER_OFFSET = 98
FILLER_COUNT = 158
QUERY_TOKEN = 1
MINIMUM_MQAR_SEQUENCE = 40
SNAPSHOT_VERSION = 4
INFERENCE_POLICIES = {"security-relevant", "all-events"}


class AsmCmUnavailable(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class _Namespace:
    revision: int = 0
    last_sequence: int = 0
    inference_state: Any = None
    next_value: int = VALUE_OFFSET
    evidence_by_value: dict[tuple[int, int], str] = field(default_factory=dict)
    token_history: list[int] = field(default_factory=list)


class AsmCmEngine:
    name = "D:asm-cm"

    def __init__(
        self,
        checkpoint: Path,
        source_root: Path,
        *,
        device: str = "cpu",
        expected_sha256: str | None = None,
        snapshot: Path | None = None,
        inference_policy: str = "security-relevant",
    ) -> None:
        self.checkpoint = checkpoint.resolve()
        self.source_root = source_root.resolve()
        self.snapshot = snapshot
        if inference_policy not in INFERENCE_POLICIES:
            raise AsmCmUnavailable(f"unsupported ASM-CM inference policy: {inference_policy}")
        self.inference_policy = inference_policy
        if not self.checkpoint.is_file():
            raise AsmCmUnavailable(f"ASM-CM checkpoint not found: {self.checkpoint}")
        if not (self.source_root / "drm_language_emitter").is_dir():
            raise AsmCmUnavailable(f"ASM source package not found: {self.source_root}")
        self.checkpoint_sha256 = sha256_file(self.checkpoint)
        if expected_sha256 and self.checkpoint_sha256 != expected_sha256:
            raise AsmCmUnavailable("ASM-CM checkpoint fingerprint mismatch")
        if str(self.source_root) not in sys.path:
            sys.path.insert(0, str(self.source_root))
        try:
            self.torch = importlib.import_module("torch")
            checkpoint_module = importlib.import_module("drm_language_emitter.checkpoint")
            inference_module = importlib.import_module("drm_language_emitter.inference")
            memory_module = importlib.import_module("drm_language_emitter.fast_weight_memory")
        except ImportError as error:
            raise AsmCmUnavailable(f"ASM-CM runtime dependency unavailable: {error}") from error
        self.InferenceState = inference_module.InferenceState
        self.FastWeightMemoryState = memory_module.FastWeightMemoryState
        self.device = self.torch.device(device)
        if self.device.type == "cuda" and not self.torch.cuda.is_available():
            raise AsmCmUnavailable("CUDA requested but unavailable")
        self.model = checkpoint_module.load_model(self.checkpoint).to(self.device).eval()
        config = self.model.config
        if not (
            config.addressable_memory
            and config.addressable_memory_backend == "fast_weight"
            and config.fast_weight_durable_memory
        ):
            raise AsmCmUnavailable("checkpoint is not durable fast-weight ASM-CM")
        self.namespaces: dict[str, _Namespace] = {}
        if snapshot and snapshot.exists():
            self._restore(snapshot)

    def reset_peak_memory_stats(self) -> None:
        if self.device.type == "cuda":
            self.torch.cuda.reset_peak_memory_stats(self.device)

    def synchronize(self) -> None:
        if self.device.type == "cuda":
            self.torch.cuda.synchronize(self.device)

    def accelerator_memory(self) -> dict[str, int] | None:
        if self.device.type != "cuda":
            return None
        return {
            "max_allocated_bytes": int(self.torch.cuda.max_memory_allocated(self.device)),
            "max_reserved_bytes": int(self.torch.cuda.max_memory_reserved(self.device)),
        }

    def _precision(self):
        if self.device.type == "cuda":
            return self.torch.autocast("cuda", dtype=self.torch.bfloat16)
        return nullcontext()

    def _initial_state(self):
        return self.model.init_inference_state(1, self.device)

    def _feed(self, state: Any, tokens: list[int]):
        state = state if state is not None else self._initial_state()
        with self.torch.inference_mode(), self._precision():
            for token in tokens:
                _, state = self.model.decode_step(
                    self.torch.tensor([token], device=self.device), state
                )
        return state

    @staticmethod
    def _remember_tokens(state: _Namespace, tokens: list[int]) -> None:
        state.token_history.extend(tokens)
        overflow = len(state.token_history) - MAX_CAUSAL_TOKEN_HISTORY
        if overflow > 0:
            del state.token_history[:overflow]

    def _predict_batched(
        self, token_history: list[int], relation_key: int
    ) -> tuple[int, float]:
        padding_count = max(0, MINIMUM_MQAR_SEQUENCE - 2 - len(token_history))
        padding = [
            FILLER_OFFSET + ((position * 37 + relation_key * 11) % FILLER_COUNT)
            for position in range(padding_count)
        ]
        tokens = [*token_history, *padding, QUERY_TOKEN, relation_key]
        with self.torch.inference_mode(), self._precision():
            output = self.model(
                self.torch.tensor([tokens], device=self.device),
                collect_diagnostics=False,
            )
            logits = output["logits"][:, -1]
        probabilities = self.torch.softmax(logits.float(), dim=-1)
        confidence, predicted = probabilities.max(dim=-1)
        return int(predicted.item()), float(confidence.item())

    def _predict_streaming(self, state: Any, relation_key: int) -> tuple[int, float]:
        working = copy.deepcopy(state if state is not None else self._initial_state())
        padding_count = max(0, MINIMUM_MQAR_SEQUENCE - 2 - working.tokens_seen)
        padding = [
            FILLER_OFFSET + ((position * 37 + relation_key * 11) % FILLER_COUNT)
            for position in range(padding_count)
        ]
        working = self._feed(working, padding)
        with self.torch.inference_mode(), self._precision():
            _, working = self.model.decode_step(
                self.torch.tensor([QUERY_TOKEN], device=self.device), working
            )
            logits, _ = self.model.decode_step(
                self.torch.tensor([relation_key], device=self.device), working
            )
        probabilities = self.torch.softmax(logits.float(), dim=-1)
        confidence, predicted = probabilities.max(dim=-1)
        return int(predicted.item()), float(confidence.item())

    @staticmethod
    def _filler(event: dict[str, Any]) -> int:
        digest = hashlib.sha256(event["operation"].encode()).digest()
        return FILLER_OFFSET + int.from_bytes(digest[:2], "big") % FILLER_COUNT

    def update(self, event: dict[str, Any]) -> dict[str, Any]:
        namespace_id = event["namespace_id"]
        state = self.namespaces.setdefault(namespace_id, _Namespace())
        sequence = int(event["sequence"])
        if sequence != state.last_sequence + 1:
            return {
                "engine": self.name,
                "namespace_id": namespace_id,
                "event_id": event["event_id"],
                "effect": "ABSTAIN",
                "reason": "SEQUENCE_GAP",
                "evidence_ids": [event["event_id"]],
                "state_revision": state.revision,
                "checkpoint_fingerprint": self.checkpoint_sha256,
                "model_inference_performed": False,
            }
        previous = copy.deepcopy(state)
        try:
            state.last_sequence = sequence
            state.revision += 1
            operation = event["operation"]
            labels = set(event.get("labels", []))
            query_relation = None
            if operation == "file.open" and "credential" in labels:
                query_relation = NETWORK_RELATION_KEY
            elif operation == "file.open" and "persistence-control" in labels:
                query_relation = PERSISTENCE_RELATION_KEY
            elif operation == "file.open" and "admin-control" in labels:
                query_relation = ADMIN_RELATION_KEY
            trigger_relation = None
            if operation == "network.connect" and "trusted-network" not in labels:
                trigger_relation = NETWORK_RELATION_KEY
            elif operation == "file.open" and "persistence-origin" in labels:
                trigger_relation = PERSISTENCE_RELATION_KEY
            elif operation == "file.open" and "admin-origin" in labels:
                trigger_relation = ADMIN_RELATION_KEY
            confidence: float | None = None
            selected: str | None = None
            model_inference_performed = False
            reset = operation == "identity.change" and "trusted-reset" in event.get("labels", [])
            trusted_network = operation == "network.connect" and "trusted-network" in labels
            if trigger_relation is not None:
                value = state.next_value
                state.next_value = VALUE_OFFSET + ((value - VALUE_OFFSET + 1) % VALUE_CAPACITY)
                state.evidence_by_value[(trigger_relation, value)] = event["event_id"]
                if self.inference_policy == "security-relevant":
                    self._remember_tokens(state, [trigger_relation, value])
                else:
                    model_inference_performed = True
                    state.inference_state = self._feed(
                        state.inference_state, [trigger_relation, value]
                    )
            elif reset or trusted_network:
                safe_value = state.next_value
                state.next_value = VALUE_OFFSET + (
                    (safe_value - VALUE_OFFSET + 1) % VALUE_CAPACITY
                )
                state.evidence_by_value.pop((NETWORK_RELATION_KEY, safe_value), None)
                if self.inference_policy == "security-relevant":
                    self._remember_tokens(state, [NETWORK_RELATION_KEY, safe_value])
                else:
                    model_inference_performed = True
                    state.inference_state = self._feed(
                        state.inference_state, [NETWORK_RELATION_KEY, safe_value]
                    )
            elif query_relation is not None:
                model_inference_performed = True
                if self.inference_policy == "security-relevant":
                    predicted, confidence = self._predict_batched(
                        state.token_history, query_relation
                    )
                else:
                    predicted, confidence = self._predict_streaming(
                        state.inference_state, query_relation
                    )
                selected = state.evidence_by_value.get((query_relation, predicted))
            elif self.inference_policy == "all-events":
                model_inference_performed = True
                state.inference_state = self._feed(
                    state.inference_state, [self._filler(event)]
                )
            evidence = [selected, event["event_id"]] if selected else [event["event_id"]]
            decision = {
                "engine": self.name,
                "namespace_id": namespace_id,
                "event_id": event["event_id"],
                "effect": "DENY" if query_relation is not None and selected else "ALLOW",
                "reason": "ASM_CM_SELECTED_CAUSAL_EVIDENCE" if selected else "NO_SELECTED_CAUSAL_EVIDENCE",
                "evidence_ids": evidence,
                "confidence": confidence,
                "state_revision": state.revision,
                "checkpoint_fingerprint": self.checkpoint_sha256,
                "model_inference_performed": model_inference_performed,
                "inference_policy": self.inference_policy,
            }
            if self.snapshot:
                self.checkpoint_state(self.snapshot)
            return decision
        except Exception:
            self.namespaces[namespace_id] = previous
            raise

    def _serialize_inference(self, state: Any) -> dict[str, Any] | None:
        if state is None:
            return None
        memory = state.addressable_memory
        memory_payload = None
        if memory is not None:
            memory_payload = {
                "matrix": memory.matrix.detach().cpu(),
                "consolidated": memory.consolidated.detach().cpu(),
                "previous_token": memory.previous_token.detach().cpu(),
            }
        return {
            "input_ids": state.input_ids.detach().cpu(),
            "completed_state": state.completed_state.detach().cpu() if state.completed_state is not None else None,
            "block_tokens": state.block_tokens.detach().cpu() if state.block_tokens is not None else None,
            "block_index": state.block_index,
            "block_size": state.block_size,
            "tokens_seen": state.tokens_seen,
            "compact": state.compact,
            "addressable_memory": memory_payload,
        }

    def _deserialize_inference(self, payload: dict[str, Any] | None):
        if payload is None:
            return None
        memory_payload = payload["addressable_memory"]
        memory = None
        if memory_payload is not None:
            memory = self.FastWeightMemoryState(
                memory_payload["matrix"].to(self.device),
                memory_payload["consolidated"].to(self.device),
                memory_payload["previous_token"].to(self.device),
            )
        move = lambda value: value.to(self.device) if value is not None else None
        return self.InferenceState(
            input_ids=payload["input_ids"].to(self.device),
            completed_state=move(payload["completed_state"]),
            block_tokens=move(payload["block_tokens"]),
            block_index=payload["block_index"],
            block_size=payload["block_size"],
            tokens_seen=payload["tokens_seen"],
            compact=payload["compact"],
            addressable_memory=memory,
        )

    def checkpoint_state(self, path: Path) -> None:
        payload = {
            "snapshot_version": SNAPSHOT_VERSION,
            "checkpoint_sha256": self.checkpoint_sha256,
            "inference_policy": self.inference_policy,
            "namespaces": {
                namespace_id: {
                    "revision": state.revision,
                    "last_sequence": state.last_sequence,
                    "next_value": state.next_value,
                    "evidence_by_value": state.evidence_by_value,
                    "token_history": state.token_history,
                    "inference_state": self._serialize_inference(state.inference_state),
                }
                for namespace_id, state in self.namespaces.items()
            },
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
        os.close(descriptor)
        temporary = Path(temporary_name)
        digest_path = path.with_suffix(path.suffix + ".sha256")
        try:
            self.torch.save(payload, temporary)
            with temporary.open("rb") as handle:
                os.fsync(handle.fileno())
            digest = sha256_file(temporary)
            os.replace(temporary, path)
            digest_path.write_text(digest + "\n")
        finally:
            temporary.unlink(missing_ok=True)

    def _restore(self, path: Path) -> None:
        digest_path = path.with_suffix(path.suffix + ".sha256")
        if not digest_path.is_file() or digest_path.read_text().strip() != sha256_file(path):
            raise AsmCmUnavailable("ASM-CM state snapshot checksum mismatch")
        payload = self.torch.load(path, map_location="cpu", weights_only=True)
        if payload["snapshot_version"] != SNAPSHOT_VERSION:
            raise AsmCmUnavailable("unsupported ASM-CM state snapshot")
        if payload["checkpoint_sha256"] != self.checkpoint_sha256:
            raise AsmCmUnavailable("state snapshot belongs to another ASM-CM checkpoint")
        if payload["inference_policy"] != self.inference_policy:
            raise AsmCmUnavailable("state snapshot belongs to another inference policy")
        self.namespaces = {
            namespace_id: _Namespace(
                revision=value["revision"],
                last_sequence=value["last_sequence"],
                next_value=value["next_value"],
                evidence_by_value={tuple(key): item for key, item in value["evidence_by_value"].items()},
                token_history=list(value["token_history"]),
                inference_state=self._deserialize_inference(value["inference_state"]),
            )
            for namespace_id, value in payload["namespaces"].items()
        }
