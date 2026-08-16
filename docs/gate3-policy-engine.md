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

## Full ASM-CM pipeline benchmark

The end-to-end benchmark consumes the frozen, real-BPF protected corpus rather
than a hand-written state fixture. For every event it updates the real ASM-CM
checkpoint, translates the result into `SecurityStateSummary`, sends the event
and state to the Rust Gate 3 process, waits for durable audit and authenticated
cache persistence, and verifies that every response remains dry-run. The
captured event policy revision must match the configured Gate 3 revision
exactly; the runner never rewrites frozen telemetry to make it pass.

```sh
AGB_GATE3_CORPUS="$PWD/var/telemetry/protected-lab/corpus.jsonl" \
ASM_CM_CHECKPOINT=../gitlab/ASM/runs/asm_c2_fw_lm_confirmation/seed_1/candidate/checkpoint_final.pt \
ASM_CM_CHECKPOINT_SHA256=96293688518fc0a2e83525af6ad28d16f39677980432762328bf4ad8aac654de \
ASM_SOURCE_ROOT=../gitlab/ASM/src \
ASM_SOURCE_REVISION=4c8eddf2f07d9aec800769323d7e1effbd64815a \
ASM_DEVICE=cuda \
AGB_GATE3_POLICY_REVISION=policy:bpf-observer-v1 \
AGB_GATE3_CACHE_KEY="replace-with-a-local-test-secret" \
make benchmark-gate3-asm-pipeline
```

The JSON report separates ASM-CM, durable Gate 3, and end-to-end latency and
records terminal confusion, audit completeness, cache contents, checkpoint and
corpus fingerprints. `ALLOW` remains an audit result only. The runner rejects a
cache containing anything other than `DENY`.

## Non-claims

This implementation validates policy semantics, real ASM-CM state handoff, cache compilation, restart,
corruption rejection, expiry, rollback boundaries, and namespace isolation. It
does not connect the cache to seccomp, BPF-LSM, AppArmor, or another enforcement
backend. That connection belongs to Gate 4 after cache lookup latency and failure
behavior are measured independently.
