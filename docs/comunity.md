# Unix-AGB: an experimental, fail-safe policy layer for behavioral security on Linux

Hello Ubuntu Security community,

I would like to introduce Unix-AGB, an open-source research project exploring how behavioral models can support Linux security decisions without replacing established controls such as AppArmor, seccomp, namespaces, or the firewall.

The project observes short process-level event sequences—such as file access, process execution, and network activity—and evaluates the relationships between those events. The goal is to identify risky behavioral compositions while preserving a conservative enforcement boundary: unusual activity alone is not treated as malicious, uncertainty should not silently become a deny decision, and enforcement must remain explicit, scoped, auditable, and reversible.

Some areas currently implemented or under evaluation include:

- Linux telemetry collection with bpftrace;
- canonical representations that preserve local entity relationships without depending on raw global identifiers;
- a frozen 2-of-3 model ensemble with seed-disagreement telemetry;
- independent human review of natural telemetry;
- separation between model decisions and policy enforcement;
- executable-scoped outbound-network policies;
- a reversible seccomp user-notification pilot;
- executable identity binding using path, device, inode, SHA-256, TGID, and process start time;
- conservative handling of timeouts, overload, stale notifications, PID reuse, fork/exec, symlinks, and binary replacement;
- JSONL audit records and reproducible benchmark artifacts.

The research results are deliberately reported with their failures intact.

Earlier experiments using raw global identifiers memorized the training data but failed to generalize, remaining close to chance on unseen entities and identifier permutations. A later canonical representation generalized successfully in synthetic tests, but one confirmation seed exceeded the preregistered false-positive-rate limit, so that experiment remained formally negative.

A subsequent preregistered test froze the existing checkpoints and evaluated a previously declared 2-of-3 canonical ensemble on a new synthetic corpus, without retraining. It achieved:

- 100% accuracy;
- 100% precision and recall;
- zero false positives and false negatives;
- 100% accuracy across tested dependency distances up to 1024;
- all seven preregistered criteria satisfied.

This is encouraging, but it is not evidence of production readiness. The successful result still belongs to the same broad synthetic problem family. It does not establish detection of unknown real-world attacks, and natural telemetry has not been relabeled as malicious merely because it looked unusual.

The current enforcement prototype is intentionally narrow. It supervises a disposable process tree and can deny external `connect()` operations for the selected executable while allowing loopback traffic and leaving processes outside that scope unchanged. It does not install a persistent or system-wide rule. The latest local pilot also eliminated stale seccomp notification wakeups and validated notification IDs before making decisions.

The next major work items are:

1. benchmark broker throughput and p50/p95/p99 decision latency under concurrency;
2. test bounded-queue behavior, overload, timeout, and broker failure;
3. integrate authenticated, revision-bound policy decisions;
4. expand controlled attack scenarios beyond the synthetic generator;
5. collect and independently review more natural Linux telemetry;
6. investigate practical integration with Ubuntu security mechanisms without weakening their guarantees.

I would especially appreciate feedback from people experienced with AppArmor, seccomp user notification, eBPF/bpftrace, audit pipelines, process identity, TOCTOU risks, and Linux security architecture.

Questions I am particularly interested in:

- Which kernel interfaces would you trust for this kind of observational and enforcement split?
- What failure semantics would you require before considering a persistent broker?
- Which Ubuntu workloads would provide useful false-positive testing?
- What adversarial tests or bypass attempts should be mandatory?
- Where should the boundary lie between a probabilistic behavioral signal and deterministic policy enforcement?

Repository: [ADD REPOSITORY URL]

The project documentation includes the preregistered criteria, negative results, implementation reports, test procedures, and generated evidence artifacts. I would be grateful for critical review—especially findings that challenge the threat model or reveal unsafe assumptions.
