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

## Telemetry consent and coverage

Production collection must not silently assume permission to observe unrelated
programs. Initial setup requires an explicit operator choice, represented by a
versioned configuration rather than an implicit command-line default:

```toml
[telemetry]
scope = "system-wide" # system-wide | protected-only | allowlist

# Used only when scope = "allowlist".
executables = ["/opt/google/chrome/chrome"]
services = []
cgroups = []
exclude_executables = []
```

The scopes have distinct coverage semantics:

- `system-wide` observes every authorized process on the host and permits only
  host-wide claims within the recorded time window;
- `protected-only` observes Unix-AGB and explicitly protected workloads, and
  makes no claim about other host activity;
- `allowlist` observes only the configured executables, services, or cgroups and
  makes no claim outside that set.

The user-facing first-run question may present the simpler choice “permit
telemetry from external programs?”, mapping `yes` to `system-wide` and `no` to
`protected-only`. Advanced configuration may then select `allowlist`. Refusal
must not be treated as an error or silently overridden.

Telemetry consent is not behavioral authorization. Observing an external
program does not grant that program permission to transmit local data. During
first-run setup, the application must therefore present a second, independent
policy step. The user chooses which behavior classes are accepted, globally or
for an exact application identity:

```toml
[data_policy]
local_file_read = "allow"              # allow | ask | deny
external_network = "ask"               # allow | ask | deny
local_file_content_egress = "deny"     # allow | ask | deny
derived_file_content_egress = "deny"   # allow | ask | deny

# A narrower application rule may reduce, but must not silently broaden, the
# global policy without explicit user confirmation.
[[data_policy.application]]
executable = "/snap/code/257/usr/share/code/code"
local_file_read = "allow"
external_network = "ask"
local_file_content_egress = "deny"
derived_file_content_egress = "deny"
allowed_destinations = []
```

The first-run UI must explain these choices in plain language and require an
explicit answer for each class. The safe initial profile permits local reads,
asks before unrelated external network access, and denies transmission of file
content or content derived from files. `ask` is fail-closed until an answer is
recorded. Consent records include policy revision, timestamp, application
identity, destinations and expiry; they are editable and revocable later.

Evaluation is operation-specific rather than a single reputation label:

- a permitted local read is benign for the local-read policy;
- a network event with no demonstrated relationship to a read is inconclusive
  for exfiltration and is evaluated separately against the network policy;
- authorized transmission is allowed and audited;
- read-then-send without sufficient causal evidence is suspicious and must not
  be described as proven exfiltration;
- content, or a tracked derivative of it, sent without authorization is a
  policy violation and may be classified malicious.

Consequently, marking a `file.open` trajectory benign never grants egress
permission. A strong exfiltration finding requires a causal chain from process
identity through file read and outbound send, including destination and policy
revision. With encrypted traffic and no pre-encryption instrumentation, the
system may report risk but must not claim that a particular file was sent.

Coverage changes what can be diagnosed, not the truth definition of a label.
Activity outside the selected scope is **not observed**; it is never inferred to
be benign, malicious, allowed, or safe. External telemetry must also remain in
its exact process namespace unless an explicit, versioned causal relationship
authorizes correlation with a protected workload.

Every capture, candidate set, frozen corpus manifest, benchmark report, and
audit summary must record the normalized scope, effective inclusions and
exclusions, configuration digest, and whether coverage was complete or partial.
Artifacts with different coverage are not directly comparable unless the
comparison explicitly accounts for that difference. Changing scope requires a
new capture revision and cannot retroactively reinterpret an existing corpus.

Independent trajectory protocol v2 records `coverage_scope`,
`coverage_config_sha256`, `subject_scope`, and `evaluation_purpose` on every
trajectory. `protected` maps to `security-efficacy`; `external` maps to
`false-positive-monitoring`. These queues retain independent labels and metrics,
but only security-efficacy test trajectories are eligible to promote Gate 2.

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
state. It permanently displays the active telemetry scope and clearly marks
partial coverage. It reports at least unique positive processes, negative decisions,
and their time window. Desktop notifications are emitted for new negative decisions
only, are grouped and rate-limited, and expose no sensitive resource path on the
lock screen by default. Notification delivery is informational and never part of
the enforcement success path.

The same GUI owns the first-run consent flow described above, but applies
changes through an authenticated policy interface. Review screens display the
specific policy dimension being labeled (for example, local read or content
egress), so a benign read cannot be mistaken for approval to transmit data.

## Production direction

Before Gate 2 promotion, select and benchmark a transactional or checksummed
backend, define fsync/WAL behavior, implement atomic snapshots, and test crash
points. SQLite is a candidate for local canonical metadata; the choice remains
an ADR rather than an architectural assumption.
