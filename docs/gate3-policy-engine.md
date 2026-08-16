# Gate 3 dry-run policy engine

Gate 3 converts a validated `SecurityStateSummary` into an auditable
`PolicyDecision`, then optionally compiles deterministic `DENY` into a short-lived
cache. Shadow `ALLOW` results are never compiled in this first slice, preventing
model-derived privilege expansion. It does not invoke an enforcement backend. Every CLI
response therefore contains `enforcement_applied: false`.

## Decision order

The evaluator applies checks in this order:

1. validate policy configuration, event, and state contracts;
2. require exact policy revision, namespace, and state/event revision;
3. enforce `restricted` and `quarantined` as unconditional `DENY` invariants;
4. require evidence, configured confidence, and model fingerprint for an
   ASM-CM `elevated` decision;
5. map validated `normal` or `monitor` state to `ALLOW`;
6. return fail-closed `ABSTAIN` for unknown, stale, incomplete, or inconsistent
   state.

Model output can restrict but cannot grant or bypass permission. Neither `ALLOW`
nor `ABSTAIN` is compiled. Cache miss, expiry, policy mismatch, and
stale state revision all return `ABSTAIN`.

## Persistence and rollback

The dry-run audit is appended and `sync_data` completes before a result becomes
cacheable. If audit persistence fails, the result is replaced by
`AUDIT_PERSISTENCE_UNAVAILABLE` and is not cached. Cache snapshots are written
through a same-directory temporary file, fsynced, renamed atomically, and bound
to the active policy revision with HMAC-SHA-256. Invalid authentication,
unsupported format, or revision mismatch rejects the entire snapshot. Rotation
or rollback clears the in-memory cache; an older policy snapshot cannot be
loaded under a newer revision.

The cache key contains the complete process namespace, operation, and SHA-256
of the canonical resource object. PID reuse and resources with the same path in
different namespaces cannot share a decision.

## Local dry-run

```sh
AGB_GATE3_INPUT=fixtures/gate3/dry-run-elevated.jsonl \
AGB_GATE3_POLICY_REVISION=policy:gate3-v1 \
AGB_GATE3_CACHE_KEY="replace-with-a-local-test-secret" \
make gate3-dry-run
```

The default audit and authenticated cache are written below `var/`. A production
secret must come from a root-readable credential file or kernel-backed secret
facility rather than a shell variable. The environment variable exists only for
this dry-run prototype.

## Non-claims

This implementation validates policy semantics, cache compilation, restart,
corruption rejection, expiry, rollback boundaries, and namespace isolation. It
does not connect the cache to seccomp, BPF-LSM, AppArmor, or another enforcement
backend. That connection belongs to Gate 4 after cache lookup latency and failure
behavior are measured independently.
