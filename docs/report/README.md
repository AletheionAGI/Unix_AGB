# Evidence report index

The numbered files in this directory are an append-only engineering journal.
They preserve the sequence of laboratory changes, but this index is the
authoritative entry point for determining current status. Gate status itself
remains authoritative in `ROADMAP.md`.

## Foundation and causal pipeline

- reports 03–05: cache fallback, BPF normalization, and gateway pipeline;
- reports 06–18: Rust broker, supervision, restart, persistence, rotation, and
  snapshot integrity;
- reports 69–72: continuous BPF observation and the current BPF-to-broker
  request adapter.
- report 73: frozen Gate 2 A–D benchmark and persistent stateful-proxy proof.
- report 74: real promoted-checkpoint ASM-CM integration and seed-1 result.
- report 75: adversarial multi-seed ASM-CM evaluation with CUDA accounting.
- report 76: independent-telemetry contract and frozen-split tooling.
- report 77: external benign telemetry across three ASM-CM seeds, with zero
  false positives, full decision coverage, and measured per-event CUDA cost.
- report 78: protected three-family multi-seed evidence that satisfies the
  frozen Gate 2 promotion criterion, with explicit controlled-lab limitations.
- report 79: snapshot-v4 vectorized query optimization with CPU equivalence and
  RTX 4090 confirmation, reducing protected-query p50 by approximately 22×.
- report 80: Gate 3 dry-run invariants, authenticated deny-only cache,
  restart/corruption tests, and isolated release lookup measurements.
- report 81: real BPF telemetry through ASM-CM state, Gate 3 durable audit, and
  authenticated deny-only cache with enforcement explicitly disabled.
- report 82: grouped audit-only persistence, mandatory pre-cache deny `fsync`,
  and one temporary process-local denial with teardown/restart rollback.
- report 83: preregistered neutral Gate 2B protocol, physically sealed holdout,
  frozen baselines, and an operator-side three-seed ASM-CM training runner.
- report 84: preserved negative Gate 2B v1 result and a separately scoped v2
  capacity/generalization diagnostic with no sealed-test access.
- report 85: identity-binding diagnostic comparing raw, canonical,
  permutation-augmented, auxiliary-matching, and explicit-equality inputs.
- report 86: fresh Gate 2B v4 raw-versus-canonical, three-seed confirmation
  scaffold with original baselines and criteria.
- report 87: frozen v4 canonical 2-of-3 ensemble confirmation on a new test.
- report 88: three promoted ASM-CM seeds through the complete Gate 3 dry-run,
  with unanimous votes, explicit disagreement telemetry, and CUDA latency.
- report 89: preregistered natural/novel-controlled ensemble validation, with
  explicit separation between selective pipeline FPR and neural inference.
- report 90: conservative review exclusion and syscall-outcome-aware BPF v2
  boundary, preserving the historical v1 evidence limitation.
- report 91: completed executable-scoped curl egress denial with loopback
  preserved, real `EACCES`, rollback by process exit, and zero stale wakeups
  after synchronization repair.
- report 92: reproducible protocol and promotion criteria for that disposable
  seccomp-user-notify egress pilot.
- report 93: adversarial process/artifact binding, notification-ID validation,
  scoped failure behavior, thread/TGID correction, and real out-of-scope
  executable isolation for the egress pilot.
- report 94: real concurrent seccomp notification latency, bounded overload,
  timeout and adapter-failure behavior, plus the preserved negative result that
  listener loss stalls and disrupts an inherited out-of-scope subprocess.
- report 95: a minimal listener-owning supervisor that fails closed for one
  protected decision, restarts a crashed policy worker, and preserves the
  out-of-scope probe while retaining listener loss as an explicit blocker.

## Administrative boundary

- reports 19–29: cache administration, socket separation, peer credentials,
  allowlists, namespaces, and the initial UID/GID matrix;
- reports 30–45: dedicated identities, storage permissions, outsider tests,
  audit capture, and privileged proof completion;
- reports 48–68: identity variants, restart proofs, malformed configuration,
  rate limiting, authoritative operator identity, authorization revisions, and
  allowlist rotation.

## Current interpretation

- Gate 0 is complete as a repository and contract foundation.
- Gate 1 and Gate 4 contain laboratory prototypes only.
- Reports marked “proof complete” establish only their narrowly stated test;
  they do not promote an entire Gate or establish production readiness.
- Gate 2 is promoted as a controlled-laboratory research prototype. This does
  not establish unknown-attack generalization, production latency, or a safe
  enforcement policy. Gate 3 now has a real-ASM-CM deny-only dry-run pipeline;
  Gate 4 now has one controlled process-local denial proof, not a production
  enforcement backend.
- Gate 2B v1 was executed and did not support the preregistered hypothesis:
  ASM-CM remained close to chance while bounded FSM/CEP reached 80%. V2/v3
  identified global-ID binding as the failure; v4 confirmed canonical long-range
  accuracy but narrowly failed its per-seed FPR criterion; v5's frozen 2-of-3
  ensemble passed all criteria on a new synthetic test. Natural unknown-attack
  validation remains outstanding.

New work should update this index when it changes the current interpretation;
small chronological reports may still be retained for reproducibility.
