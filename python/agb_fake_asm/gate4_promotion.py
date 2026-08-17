"""Fail-closed evaluation primitives for the Gate 4 promotion matrix."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any


PROMOTION_PROTOCOL = "unix-agb-gate4-promotion-v1"
REQUIRED_DOMAINS = (
    "gate3_decision_integration",
    "real_application_coverage",
    "concurrency_endurance",
    "authenticated_policy_lifecycle",
    "failure_update_matrix",
    "namespace_application_isolation",
    "production_resource_latency",
    "ubuntu_boot_matrix",
)
GATE3_ENTRY_FIELDS = (
    "cache_key", "decision_id", "namespace_id", "operation", "resource_sha256",
    "effect", "policy_revision", "state_revision", "evidence_sha256", "expires_epoch",
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sign_evidence(evidence: dict[str, Any], secret: bytes) -> dict[str, Any]:
    unsigned = dict(evidence)
    unsigned.pop("hmac_sha256", None)
    return {**unsigned, "hmac_sha256": hmac.new(secret, canonical_json(unsigned), hashlib.sha256).hexdigest()}


def verify_evidence(evidence: dict[str, Any], secret: bytes, revision: str) -> tuple[bool, str]:
    signature = evidence.get("hmac_sha256")
    if not isinstance(signature, str) or len(signature) != 64:
        return False, "EVIDENCE_SIGNATURE_MISSING"
    unsigned = dict(evidence)
    unsigned.pop("hmac_sha256", None)
    expected = hmac.new(secret, canonical_json(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return False, "EVIDENCE_SIGNATURE_INVALID"
    if evidence.get("protocol") != PROMOTION_PROTOCOL:
        return False, "PROTOCOL_MISMATCH"
    if evidence.get("policy_revision") != revision:
        return False, "POLICY_REVISION_MISMATCH"
    if evidence.get("supported") is not True:
        return False, "DOMAIN_NOT_SUPPORTED"
    if evidence.get("protected_fail_open") != 0:
        return False, "PROTECTED_FAIL_OPEN"
    if evidence.get("cross_scope_effects") != 0:
        return False, "CROSS_SCOPE_EFFECT"
    if not isinstance(evidence.get("artifact_sha256"), str) or len(evidence["artifact_sha256"]) != 64:
        return False, "ARTIFACT_DIGEST_INVALID"
    return True, "SUPPORTED"


def authorize_gate3_deny(
    snapshot: dict[str, Any], secret: bytes, revision: str, cache_key: str, now_epoch: int
) -> tuple[bool, str, dict[str, Any] | None]:
    """Authorize only one authenticated, current Gate 3 network DENY."""
    if snapshot.get("format_version") != 1:
        return False, "CACHE_FORMAT_UNSUPPORTED", None
    if snapshot.get("policy_revision") != revision:
        return False, "POLICY_REVISION_MISMATCH", None
    entries = snapshot.get("entries")
    if not isinstance(entries, list) or not isinstance(snapshot.get("hmac_sha256"), str):
        return False, "CACHE_INVALID", None
    try:
        normalized = [{field: entry[field] for field in GATE3_ENTRY_FIELDS} for entry in entries]
    except (KeyError, TypeError):
        return False, "CACHE_INVALID", None
    payload = json.dumps([1, revision, normalized], separators=(",", ":")).encode()
    expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(snapshot["hmac_sha256"], expected):
        return False, "CACHE_AUTHENTICATION_FAILED", None
    matches = [entry for entry in normalized if entry["cache_key"] == cache_key]
    if len(matches) != 1:
        return False, "DECISION_NOT_UNIQUE", None
    decision = matches[0]
    if decision["policy_revision"] != revision:
        return False, "DECISION_REVISION_MISMATCH", None
    if decision["effect"] != "DENY":
        return False, "DECISION_NOT_DENY", None
    if decision["operation"] != "network.connect":
        return False, "DECISION_OPERATION_MISMATCH", None
    if not isinstance(decision["expires_epoch"], int) or decision["expires_epoch"] <= now_epoch:
        return False, "DECISION_EXPIRED", None
    return True, "GATE3_DENY_AUTHORIZED", decision


def evaluate_matrix(evidence: list[dict[str, Any]], secret: bytes, revision: str) -> dict[str, Any]:
    by_domain: dict[str, list[dict[str, Any]]] = {}
    for item in evidence:
        by_domain.setdefault(str(item.get("domain", "")), []).append(item)

    results: dict[str, dict[str, Any]] = {}
    for domain in REQUIRED_DOMAINS:
        candidates = by_domain.get(domain, [])
        checks = [verify_evidence(item, secret, revision) for item in candidates]
        accepted = [reason for ok, reason in checks if ok]
        results[domain] = {
            "supported": bool(accepted),
            "reason": "SUPPORTED" if accepted else (checks[-1][1] if checks else "EVIDENCE_MISSING"),
            "evidence_count": len(candidates),
        }

    accepted_artifacts = {
        str(item.get("artifact_sha256"))
        for item in evidence
        if verify_evidence(item, secret, revision)[0]
    }
    artifact_consistent = len(accepted_artifacts) == 1
    supported = all(item["supported"] for item in results.values()) and artifact_consistent
    return {
        "protocol": PROMOTION_PROTOCOL,
        "policy_revision": revision,
        "domains": results,
        "protected_fail_open": sum(int(item.get("protected_fail_open", 0)) for item in evidence),
        "cross_scope_effects": sum(int(item.get("cross_scope_effects", 0)) for item in evidence),
        "artifact_sha256": next(iter(accepted_artifacts)) if artifact_consistent else None,
        "artifact_consistent": artifact_consistent,
        "supported": supported,
        "gate4_status": "promoted" if supported else "controlled-prototype",
    }


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
