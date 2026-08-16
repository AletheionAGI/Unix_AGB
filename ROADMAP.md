# Unix-AGB Roadmap

Original date: 2026-08-15

## Current status

Unix-AGB has completed the reviewable **Gate 0 — architecture and repository
foundation** artifact. Gate 1 is a laboratory prototype: real subprocesses can
be traced and normalized, and Gate 4 has a narrowly scoped seccomp proof. No
production observer or system-wide enforcement service exists yet.

| Gate | Scope | Status |
|---:|---|---|
| 0 | Architecture, licensing, contracts, threat model, benchmark plan | Complete |
| 1 | Ubuntu observer and canonical event pipeline | Prototype |
| 2 | ASM-CM state runtime and persistence | Promoted controlled-lab prototype |
| 3 | Explicit policy engine and dry-run decisions | Deny-only dry-run prototype |
| 4 | Narrow deterministic enforcement pilot | Laboratory prototype |
| 5 | AI-agent capability broker | Not started |
| 6 | Ubuntu-derived developer preview | Not started |
| 7 | Formal decision on custom-kernel necessity | Not started |

## Gate 0 — foundation

- establish repository governance, copyright, licenses, notice, and citation;
- split the architecture into implementable contracts and threat-model docs;
- define event, state, policy-decision, and enforcement-record schemas;
- freeze a reproducible benchmark protocol with strong baselines;
- define responsible disclosure and third-party dependency tracking.

Exit criterion: contracts, risks, non-claims, benchmark gates, and the initial
implementation skeleton are reviewable and internally consistent.

Implemented Gate 0 artifacts include versioned JSON Schemas, deterministic
fixtures, an append-only JSONL prototype store, stable process namespaces, an
audit-only Rust pipeline, a fake Python ASM boundary, a fake enforcer, and
automated tests. “Complete” here describes the repository-foundation gate; it
does not validate the security system or promote the project to Gate 1.

## Gate 1 — Ubuntu observer

- collect a minimal process/exec/file/network event subset;
- derive stable process identity from boot identity plus process start data;
- normalize events through the AGB Event Gateway;
- append exact events and provenance to the canonical store;
- expose audit-only CLI and health diagnostics;
- measure drops, throughput, CPU, memory, and storage overhead.

The repository includes a cooperative laboratory slice with real Rust
subprocesses, `strace` normalization, the Rust gateway, and process-local
Landlock denial. It also includes an external seccomp-user-notify laboratory
broker connected to the gateway. A production observer, durable broker, and
system-wide enforcement adapter remain outstanding.

The enforcement edge now has a tested versioned/expiring cache primitive with
fail-closed misses. It is not yet wired into a persistent broker or promoted to
the system-wide enforcement path.

No automatic blocking occurs in this gate.

### 2026-08-15 implementation status

Completed and documented in `docs/report/03` through `docs/report/46`:

- persistent Rust policy broker and gateway handoff;
- authenticated admin socket with peer UID/GID allowlists, rate limiting,
  restart supervision, and audit JSONL;
- atomic/fsync snapshot rotation with checksum/HMAC validation;
- seccomp/user-notify and BPF normalization laboratory pipelines;
- privileged laboratory proof with real allowlisted and outsider accounts,
  including persisted `admin-ok` and `peer-not-allowlisted` decisions.

Still outstanding:

- production observer and non-cooperative system-wide enforcement;
- explicit telemetry-consent configuration with `system-wide`, `protected-only`,
  and executable/service/cgroup `allowlist` scopes;
- first-run, revocable data-use policy for local reads, external networking,
  file-content egress, derived-content egress, destinations, and per-application
  exceptions; `ask` must fail closed and a benign read must never authorize
  transmission;
- propagation of effective coverage and its configuration digest into captures,
  frozen manifests, reports, audits, and the operator GUI;
- Gate 2 state runtime, Gate 3 policy engine, and Gates 5–7 deliverables.

Completed privileged variants, including shared-group and UID-only execution,
audit persistence, and admin-server restart, are recorded in
`docs/report/53_dual_identity_restart_proof_complete_20260815.md`.

## Gate 2 — ASM-CM state runtime

The repository now contains a deterministic `StateEngine` seam, a Python
stateful proxy, and a real promoted-checkpoint ASM-CM adapter behind the
Unix-socket boundary. Both have checksummed snapshots and participate in the
frozen A–D comparison harness. The real seed-1 integration validates checkpoint
loading, evidence selection, restart, and corrupt-state rejection, not general
security efficacy. Three promoted checkpoints pass the frozen adversarial v2
corpus without seed variance. The later protected three-family corpus satisfies
the controlled Gate 2 promotion criterion; independent natural adversarial
telemetry, replay from the canonical store, and production resource accounting
remain outstanding.

The independent-telemetry contract and leakage-resistant split freezer are now
implemented. Collection and external labeling remain outstanding; no synthetic
fixture may satisfy that promotion requirement.

Independent trajectory protocol v2 separates protected security-efficacy from
external false-positive monitoring. The freezer and review UI report both, while
Gate 2 promotion consumes only the protected security-efficacy test queue.
The first frozen external corpus now records 50 benign trajectories (37 test),
including explicit reviewer-confidence strata. Three ASM-CM seeds produced zero
false positives and full decision coverage, but approximately 20 ms median
per-event neural latency. This is false-positive evidence only; it neither
measures malicious recall nor promotes Gate 2. See report 77.

The protected-corpus laboratory now generates three independently named causal
families from real BPF-observed syscalls: credential egress context, controlled
persistence origin, and controlled administrative origin. Every terminal action
is confined to laboratory files or loopback, exact-path semantic labels are
policy-derived, and class labels come only from the orchestrator's handshaken
ground truth. The frozen capture contains 180 trajectories; its 141-trajectory
test split produced 100% accuracy, recall, and coverage on all three ASM-CM seeds
versus 67,38% sequence-baseline accuracy, promoting Gate 2 under the frozen
criterion. This is controlled-laboratory evidence, not unknown-attack or
production-enforcement validation. See report 78.

The post-promotion snapshot-v4 adapter defers neural work until protected
queries and evaluates the preserved MQAR sequence in one vectorized forward
pass. CPU equivalence checks across relation keys retained identical predictions
and confidence while reducing isolated query latency by 13–25×. The subsequent
RTX 4090 multi-seed run preserved the promoted confusion matrix and reduced
protected-query p50 from roughly 515–521 ms to 22,9–23,5 ms (about 22×), while
cutting inference count from 212 to 141. This remains too slow for synchronous
syscall enforcement; Gate 3 must compile deterministic decisions for the hot path.

- create isolated state per security namespace;
- implement event-to-state updates and deterministic revisions;
- account separately for retained state, snapshots, RSS/VRAM, and event storage;
- implement atomic snapshot and fail-closed restore;
- detect checkpoint, schema, configuration, store-revision, and sequence gaps;
- test restart, corruption, replay, PID reuse, and cross-namespace isolation.

## Gate 3 — policy engine

The first Gate 3 slice is implemented in dry-run mode. It validates event/state
contracts and exact revisions, applies static restriction invariants, converts
incomplete or low-confidence state to fail-closed `ABSTAIN`, audits before cache
compilation, and persists an authenticated, atomic, expiring deny-only cache.
Shadow `ALLOW` is deliberately not compiled, so model state cannot expand
privilege. Restart, corruption, expiry, rollback, stale revision, and namespace
isolation are covered by Rust tests. Two release microbenchmark runs measured
isolated in-process cache hits at 65 ns p50, 66–113 ns p95, and 83–114 ns p99
over 100.000 iterations each; this excludes IPC and enforcement overhead. See
report 80.

- encode non-negotiable static invariants;
- map state and authorized canonical evidence into risk bands;
- implement `ABSTAIN` and explicit reason codes;
- persist one compact, deduplicated record per exact positive process identity;
- retain detailed negative decisions and their minimum reproducible causal evidence;
- compile versioned, expiring decisions into a local policy cache;
- support validation, dry-run, audit traces, rollback, and operator review;
- prohibit state-derived privilege expansion.

## Gate 4 — enforcement pilot

- select the smallest suitable AppArmor, BPF-LSM, cgroup, or systemd surface;
- enforce one controlled, reversible denial or containment class;
- keep neural inference and network calls outside the hot path;
- measure p50/p95/p99 enforcement latency and cache behavior;
- verify base-policy behavior during daemon, model, GPU, and store failures;
- expose read-only positive/negative counters for a later local GUI;
- group and rate-limit desktop notifications for new negative decisions;
- exercise rollback and recovery boot.

Promotion requires acceptable false positives, bounded resources, reliable
restart, safe fallback, complete provenance, and no observed cross-namespace
leakage in the defined test suite.

## Gate 5 — AI-agent security runtime

- assign explicit identities to agents and tool chains;
- implement a capability broker with least-context evidence disclosure;
- isolate state and evidence per agent and tenant;
- constrain filesystem, network, secret, and execution access;
- test prompt injection, confused-deputy behavior, tool abuse, and exfiltration;
- ensure explanations cannot mutate canonical enforcement decisions.

## Gate 6 — developer preview

- produce Debian packages and systemd units;
- define signed artifacts, checkpoint allowlists, and update/rollback paths;
- provide `agbctl doctor`, diagnostics, recovery mode, and operator docs;
- build an Ubuntu-derived development image;
- publish reproducible benchmark and limitation reports.

## Gate 7 — kernel decision

Perform a formal review:

```text
Do existing AppArmor, LSM, BPF, audit, cgroup, namespace, seccomp, and systemd
interfaces provide the required information, timing, and security properties?

YES → remain on the stock Ubuntu kernel.
NO  → document the missing capability and prototype the smallest viable patch.
```

A custom kernel is justified only by measured missing hooks, unavailable
security information, an enforcement point that cannot otherwise be reached,
unacceptable measured overhead, or a required property that existing
interfaces cannot guarantee.

## Cross-cutting validation

Every gate must preserve:

- deterministic base enforcement and safe degraded operation;
- explicit namespaces and authorization-before-resolution;
- canonical evidence with provenance and policy revision;
- bounded queues, state accounting, rate limits, and recovery tests;
- comparison with deterministic rules, time windows, and conventional scores;
- precise distinction between proposed, implemented, tested, and validated.
