# AGB contracts

The canonical machine-readable definitions live in `schemas/v1/`. All external
messages carry `schema_version: "1.0"`. Breaking changes require a new schema
directory and explicit migration rules.

## SecurityEvent

An immutable observation accepted by the Event Gateway. Required semantic
checks beyond JSON Schema:

- `event_id` is globally unique for the store;
- `sequence` strictly increases per `namespace_id`;
- `namespace_id` matches the normalized subject identity;
- process identity contains boot ID, PID, and process start time;
- `occurred_at` is RFC 3339 UTC;
- fields and line size remain below configured limits.

## SecurityStateSummary

An associative or deterministic summary for one namespace and state revision.
It is not canonical evidence. `confidence` is optional; a state engine must not
invent a calibrated probability when it only has a rule score.

## PolicyDecision

A versioned dry-run or enforceable decision with explicit reason codes and
evidence IDs. Gate 0 always sets `mode: "audit"`; `ALLOW` and `DENY` are shadow
outcomes for comparison and are never evidence that host enforcement occurred.

## CompiledDecision

A deterministic, expiring cache record derived from an audited policy decision.
Its key binds the exact namespace, operation, and canonical resource digest. It
also binds policy and state revisions plus an evidence digest. The first Gate 3
slice compiles only `DENY`; `ALLOW` remains a shadow result and permission comes
from the deterministic base policy. `ABSTAIN` remains an explicit miss/fallback
outcome. Gate 3 snapshots authenticate the ordered record set and policy revision
with HMAC.

## EnforcementRecord

Records what an adapter actually applied. The default Gateway path uses backend
`fake` and `applied: false`; the seccomp laboratory broker emits a separate
external record with backend `seccomp-user-notify`. A decision alone is never
proof of enforcement.

## Compatibility

Consumers reject unknown major versions. Unknown optional fields in the same
major version may be retained or ignored. Persisted records are never rewritten
silently.
