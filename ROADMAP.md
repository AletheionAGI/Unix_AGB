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
| 3 | Explicit policy engine and dry-run decisions | Real ASM-CM deny-only dry-run pipeline |
| 4 | Narrow deterministic enforcement pilot | Controlled process-local denial prototype |
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

### Gate 2B — causal generalization challenge

The next scientific gate is preregistered separately from the controlled Gate 2
engineering promotion. It uses abstract relation/entity tokens, held-out
agent/tool composition, a completely hidden family, causal distances from 4 to
1024, bounded-state FSM/CEP/window/score controls, and a learned GRU control.
Baselines are fingerprinted before ASM-CM training, and test labels remain
unevaluated until three candidate checkpoints are frozen. A consistent
five-percentage-point advantage at long distance and on the hidden family is
required; a tie or loss is an explicit refutation. The completed v1 run did not
support the hypothesis: all ASM-CM seeds remained close to chance while bounded
FSM/CEP reached 80%. That result remains frozen. A separate v2 diagnostic gates
the distance ladder on balanced 2/8/32-example capacity checks and never accepts
the sealed test corpus; see `docs/gate2b-causal-generalization.md` and
`docs/gate2b-v2-diagnostic.md`.
The v2/v3 diagnostics localized the failure to global-ID representation:
trajectory-local canonical IDs reached 100% on new and permuted entities while
raw IDs remained near chance. V4 confirmed 99.375–100% canonical accuracy and
100% at distances 256/1024 across three seeds, but correctly retained a negative
formal verdict because seed 3 FPR was 1.25% against a 1% limit. V5 froze those
models and predeclared a 2-of-3 ensemble on a new test; it passed all seven
criteria with 100% accuracy/recall/precision and zero FP/FN, while recording
0.625% seed disagreement per split. These results remain synthetic-family
evidence, not natural unknown-attack validation. See `docs/gate2b-v3-binding.md`,
`docs/gate2b-v4-canonical-confirmation.md`, and `docs/gate2b-v5-ensemble.md`.

Canonicalization and decision voting now also have reusable operational seams.
The Gate 3 dry-run can load three telemetry-compatible checkpoints, records
member disagreement, and defaults to `ABSTAIN` on a split vote; majority 2-of-3
requires an explicit opt-in. This is pipeline plumbing, not validation of the
frozen v4 models on natural telemetry. The subsequent three-seed CUDA dry-run
was unanimous on all 987 protected-corpus events, retained TN=70/TP=71 with zero
FP/FN/ABSTAIN, and measured 54.37 ms p95 end-to-end latency. This remains
controlled-laboratory evidence with enforcement disabled. See
`docs/asm-cm-operational-ensemble.md` and report 88.

A separate natural/novel-controlled validation rejected the previously observed
corpora/family names and froze all criteria before GPU evaluation. It passed the
declared criteria: the natural test had TN=697/FP=0/ABSTAIN=0 and the delayed
controlled test had TN=69/TP=71/FP=0/FN=0/ABSTAIN=0, with no seed disagreement.
The natural stratum triggered zero neural inference, so it measures selective
pipeline false positives rather than neural FPR on sensitive natural queries.
The controlled families remain laboratory variations of the same semantic
relations, not natural unknown attacks. See
`docs/gate3-natural-controlled-validation.md` and report 89.

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

The full dry-run path now consumes the frozen protected BPF corpus through the
real ASM-CM adapter and a validated `SecurityStateSummary`. It persists one
audit decision per event and rejects any cache snapshot containing a non-`DENY`
entry. The RTX 4090 run produced TN=70, TP=71, FP=0, FN=0 on the test split,
with end-to-end latency of 4,66 ms p50, 22,96 ms p95, and 25,14 ms p99. Durable
audit/cache persistence alone cost 4,35 ms p50, making it the next common-path
optimization target. Every response still reports `enforcement_applied: false`.
See report 81.

- encode non-negotiable static invariants;
- map state and authorized canonical evidence into risk bands;
- implement `ABSTAIN` and explicit reason codes;
- persist one compact, deduplicated record per exact positive process identity;
- retain detailed negative decisions and their minimum reproducible causal evidence;
- compile versioned, expiring decisions into a local policy cache;
- support validation, dry-run, audit traces, rollback, and operator review;
- prohibit state-derived privilege expansion.

## Gate 4 — enforcement pilot

The first controlled pilot applies one two-second, exact-process denial to a
temporary marker through the existing Landlock laboratory workload. The deny
audit is durable before cache compilation, access fails with `EACCES`, cache
expiry is observed, and teardown plus clean restart restores access. No system
path or unrelated process is modified. Because Landlock cannot relax policy in
a running process, rollback is explicitly process replacement. See report 82.

A second disposable pilot restricts external `connect` calls for an exact
`/usr/bin/curl` process tree through seccomp-user-notify. Loopback and local
resolver access remain available, decoded external IPv4/IPv6 calls receive
`EACCES`, process exit removes the filter, and no system-wide rule is installed.
The corrected run observed zero stale listener wakeups. This validates the
narrow mechanism only; persistent service lifecycle, authenticated policy
distribution, overload behavior, and unrelated-executable isolation remain
promotion blockers. Adversarial identity binding now covers TGID/start time,
device/inode/SHA-256, notification-ID validity, replacement/PID-reuse tests,
scoped failure behavior, and a real inherited out-of-scope executable probe.
The concurrent userspace notification benchmark measured 1.148 ms p50,
1.939 ms p95, and 2.366 ms p99 in its normal 256-attempt scenario. Bounded
overload, decision timeout, and adapter failure denied only the target while
the live broker allowed an inherited out-of-scope probe. Total listener loss
produced a negative result: the disposable group stalled until its two-second
watchdog terminated it, and the inherited out-of-scope subprocess was also
disrupted. Formal live-listener latency/overload measurement is complete;
a subsequent prototype retained the listener in a minimal supervisor and
restarted an injected crashed policy worker. All 64 target calls were denied,
the out-of-scope probe remained allowed, exactly one replacement generation was
observed, and recovery-path latency was 1.276 ms p50, 4.081 ms p95, and
4.396 ms p99. This narrows recoverable failure to the optional worker;
persistent supervisor lifecycle, authenticated policy distribution, and safe
listener-owner failure/recovery remain promotion blockers. See reports 91–95.

A retained-listener guardian then transferred the listener through
`SCM_RIGHTS`, injected broker-generation exit after eight completed responses,
and made generation 2 ready in 9.701 ms. All 256 protected calls were denied,
the out-of-scope probe remained allowed, and the workload completed without a
watchdog. The sibling broker deliberately uses an exact-process network rule:
host Yama policy prevents it from decoding the protected process's `sockaddr`
without expanding ptrace authority. In-flight broker death, authenticated
handoff, guardian failure, and protected-group teardown remain blockers. See
report 96.

The in-flight follow-up killed generation 1 after its eighth `RECV`, after a
guardian-visible lease but before `SEND`. The retained notification ID remained
valid. The guardian independently mapped TID to the protected TGID, returned
`EACCES` in 123 µs, and made generation 2 ready in 9.839 ms. All 256 protected
calls were denied, the out-of-scope probe remained allowed, and no teardown was
needed. A crash between kernel `RECV` completion and lease publication,
authenticated/revision-bound handoff, restart-loop bounds, and guardian failure
with protected-cgroup teardown remain blockers. See report 97.

The next reversible sequence added a 50 ms pre-lease recovery deadline,
process-group teardown that preserved an unrelated control process, a two-per-
60-second restart budget, Unix `SO_PEERCRED` plus nonce/expiry/revision/HMAC
handoff validation, and an external launcher response to guardian death. The
repository also introduced a disabled-by-default systemd packaging scaffold.
Process groups still substitute for delegated cgroups, and the enforcement
runtime is intentionally not promoted. See reports 98–100.

The cgroup follow-up ran the in-flight seccomp proof and a guardian-failure
workload inside separate user-systemd transient services. All protected members
matched the exact cgroup v2 ControlGroup, direct `cgroup.kill` executed after
50.221 ms, an unrelated process survived, and both units were collected to
`LoadState=not-found`. This validates a delegated user cgroup boundary, not a
privileged persistent enforcement service. See report 101.

The packaging follow-up installed a lifecycle-only Debian package in a
disposable Ubuntu 26.04 VM. It remained inactive by default, recovered its
revision-bound local health service after a cold boot, and left no package,
unit, account, process, listener, cgroup, or file residue after purge. The
graceful Multipass reboot result remained negative because Multipass 1.16.3
stalled after the guest reset and required daemon recovery. The runtime reports
`enforcement_active: false`, so persistent enforcement and graceful reboot
recovery remain outstanding. See report 102.

The identical package artifact then passed the compatibility matrix on Ubuntu
24.04.4: inactive-by-default installation, explicit activation, guest-driven
graceful reboot recovery, exact revision health response, and residue-free
purge. This narrows report 102's reboot failure to its observed Multipass 1.16.3
control path/environment; it does not prove the cause. Persistent enforcement
remains unimplemented. See report 103.

The next opt-in package connected a root exact-launch wrapper to a persistent
dedicated guardian through authenticated listener handoff. The same
reproducible package hash on Ubuntu 24.04.4 and 26.04 allowed loopback, denied
protected external connects with `EACCES`, preserved unregistered external
networking, recovered a worker generation, enforced a bounded restart budget,
terminated only the protected process group after guardian death, recovered
the guardian across guest reboot, and purged without residue. This supports the
narrow exact-launch laboratory mechanism only; retroactive attachment and
production/system-wide enforcement remain outstanding. Ubuntu 26.04 also
retained an unrelated `grub2-common`/virtual-fd0 degraded-boot result. See
reports 104–105.

Gate 4 is not promoted. A stricter promotion protocol now requires eight
independent evidence domains: real Gate 3 decision binding, real application
coverage, concurrency/endurance, authenticated policy lifecycle, failure and
update behavior, namespace/application isolation, production resource and
latency budgets, and the Ubuntu boot/package matrix. Its evaluator fails
closed on missing or unauthenticated evidence and retains
`gate4_status: controlled-prototype` until every domain passes under one frozen
revision and artifact. See report 106.

Implementation of the first promotion domain has started under a separately
frozen protocol. Package 0.3.0 introduces an opt-in Gate 3 service-supervision
mode: seccomp interception exists before application `exec`, the launcher and
guardian independently bind the target to the BPF process-namespace identity,
and each external connect consults the current authenticated Gate 3 cache. A
bad reload retains the last authenticated snapshot; initial invalid policy
prevents activation; expiry or an authenticated empty rotation removes the
restriction. The explicit v1 mapping is trajectory-level external-egress
containment, not destination-specific enforcement. Unit/package validation is
not promotion evidence; the long-lived VM transition test remains pending.
See report 107.

The first Ubuntu 24.04 controlled run of package 0.3.0 demonstrated a live
empty-cache -> exact-namespace `DENY` -> tampered-cache -> authenticated-empty
transition. The protected service changed from `ECONNREFUSED` to `EACCES`,
retained `EACCES` across cache corruption, and returned to `ECONNREFUSED` after
valid rotation; an unprotected control was unaffected and purge left no
residue. A restart-readiness race found during negative testing was fixed with
a bounded fail-closed launcher wait and the full matrix was rerun. This still
uses controlled cache injection, so the real Gate 3 integration promotion
domain remains unsupported. See report 108.

Package 0.3.1 then replaced the handcrafted trigger with the three frozen Gate
3 ensemble members and the real Rust policy compiler while the protected
service remained alive. A controlled malicious trajectory rebound to the
service's exact namespace produced one unanimous, revision-bound compiled
`DENY` originating at `file.open`; atomic cache publication caused the next
external connect to return `EACCES`, preserved an unprotected control, and an
authenticated empty rotation restored baseline behavior. This validates the
complete controlled model-to-kernel chain, but the rebound input was not newly
captured BPF telemetry and is explicitly ineligible for promotion. See reports
109–110.

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

## Current next validation boundary

Review exclusion, syscall-outcome correlation, process parent/command identity,
and distinct socket/bind/connect telemetry are implemented. A conservative
re-audit excluded all 833 historical natural trajectories because the v1
capture observed requests rather than syscall outcomes. This is an explicit
negative evidence-quality result, not a reclassification as malicious.

The next operator-assisted step is to compile the v2 BPF observer with host
privileges, capture a fresh naturalistic benign protected-query corpus, review
and conservatively audit it, then freeze it. Only then compare sequential and
opt-in parallel ensemble latency on the same frozen GPU workload. Enforcement
remains out of scope until natural protected queries produce decisive evidence
with bounded false positives and disagreement.
