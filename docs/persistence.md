# Persistence

## Gate 0 canonical store

The development backend is append-only JSONL. Each accepted event is fully
serialized before writing, appended as one line, flushed, and synchronized with
`sync_data` before the gateway updates its in-memory replay index or
acknowledges it. A failed append may therefore be retried in the same process
without being mistaken for a replay.

Startup validates every complete record and fails closed on malformed or
semantically invalid input. JSONL still has no transaction framing for a torn
final append and provides no tamper resistance; operators must repair or
restore the canonical file explicitly rather than having the gateway infer a
valid prefix.

## Policy cache and audit

Persistent cache entries are accepted only when authenticated with
HMAC-SHA256 through a non-empty `AGB_CACHE_KEY`. Without a key, the broker uses
only its process-local cache and neither loads nor writes unauthenticated cache
entries. Cache and audit appends are flushed and synchronized before success is
reported. If required cache or audit persistence fails, the protected decision
is converted to the documented fail-closed denial.

## Runtime state

The fake state engine reconstructs state from accepted events. Future snapshots
must include:

- schema version;
- checkpoint fingerprint;
- configuration fingerprint;
- namespace and state revision;
- last committed event sequence;
- canonical-store revision;
- content checksum.

Restore fails closed on incompatible fingerprints, missing canonical events,
sequence regression, or checksum failure. Reinitialization cannot broaden
privilege.

The Gate 2 deterministic proxy now implements the first version of this
contract in `python/agb_fake_asm/persistent_engine.py`: it persists an engine
fingerprint, configuration fingerprint, per-namespace revision and last event
sequence, causal flags, evidence IDs, and a content checksum through an atomic
temporary-file replacement followed by file and directory synchronization.
Restore rejects corruption, incompatible formats, and fingerprint changes.
Sequence gaps return `ABSTAIN` without checkpointing the incomplete update.

This checksum detects accidental corruption but is not authentication against
an attacker who can rewrite both content and digest. Signed or keyed snapshots
and reconciliation with a durable canonical-store revision remain promotion
requirements for a real ASM-CM backend.

The real ASM-CM adapter persists only per-namespace inference tensors and
canonical evidence mappings; the shared 84M-parameter model remains in its
fingerprinted external checkpoint. State snapshots are written through an
atomic replacement, paired with a SHA-256 sidecar, and loaded with PyTorch's
restricted `weights_only` deserializer. Restore verifies both the state digest
and originating model-checkpoint digest before exposing any recovered state.

## Decision-aware retention

The production observer may inspect the complete authorized host event stream,
but persistence is decision-aware. In this document, a **positive** process is
one whose evaluated effect remains `ALLOW`; a **negative** is a risk or policy
decision that results in `DENY`. These terms describe policy outcomes, not the
positive/negative class convention of an ML training library.

Positive observations are never erased as though the process had not existed.
They are compacted into one durable record per exact process identity:

```text
host_id + boot_id + pid + start_time_ns
```

Repeated positive events update that record instead of appending duplicate
process rows. The minimum positive record contains the process identity and
executable, first and last observation times, total observation count, distinct
operation classes, a causal-context digest, and the latest policy revision and
consolidated decision. PID alone is never a deduplication key because the kernel
may reuse it.

Negative decisions retain more evidence: the terminal event, decision and
reason code, the minimum causal predecessor set needed to reproduce or explain
the result, policy/model revisions, and audit timestamps. Compaction must not
remove evidence referenced by a negative decision or make a previously issued
decision unauditable.

The retained positive table and negative audit log are separate from transient
observer buffering. Crash consistency, authenticated integrity, bounded causal
retention, and migration of both formats remain production requirements.

## Operator presentation

A future local GUI reads retention statistics through a read-only administrative
interface; it does not read storage files directly and cannot mutate enforcement
state. It reports at least unique positive processes, negative decisions, and
their time window. Desktop notifications are emitted for new negative decisions
only, are grouped and rate-limited, and expose no sensitive resource path on the
lock screen by default. Notification delivery is informational and never part of
the enforcement success path.

## Production direction

Before Gate 2 promotion, select and benchmark a transactional or checksummed
backend, define fsync/WAL behavior, implement atomic snapshots, and test crash
points. SQLite is a candidate for local canonical metadata; the choice remains
an ADR rather than an architectural assumption.
