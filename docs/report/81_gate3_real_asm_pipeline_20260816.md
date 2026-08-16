# Gate 3 real ASM-CM pipeline

Date: 2026-08-16

Gate 3 now accepts state produced by the real promoted-checkpoint ASM-CM
adapter over the frozen protected BPF corpus. The runner preserves every
captured event, requires its `policy_revision` to match Gate 3, constructs the
versioned `SecurityStateSummary`, and invokes the Rust dry-run policy boundary.

The measured path is:

`BPF telemetry -> ASM-CM -> SecurityStateSummary -> Gate 3 -> durable audit -> authenticated deny-only cache`

The runner independently checks that every response contains
`enforcement_applied: false`, that the audit has exactly one record per input
event, and that every compiled cache entry is `DENY`. Model `ALLOW` is visible
in audit output but cannot enter the cache.

An initial CPU integration run processed the 141 test trajectories and 987 BPF
events from dataset
`ae165d68603180df880de933ed8fb6a84137aac14cc1e8bdab65de259dd53740`.
It produced 916 shadow `ALLOW`, 71 `DENY`, no `ABSTAIN`, and terminal confusion
TN=70, TP=71, FP=0, FN=0. This run proves functional wiring only.

The subsequent RTX 4090 run preserved that exact confusion matrix and processed
all 987 events without abstention. ASM-CM latency was 34.091 µs p50, 17.918 ms
p95, and 19.205 ms p99; most ordinary events require no neural inference.
Durable Gate 3 audit/cache latency was 4.346 ms p50, 6.516 ms p95, and 7.932 ms
p99. End-to-end latency was 4.663 ms p50, 22.963 ms p95, and 25.138 ms p99. The
987-record audit was complete, all 71 cache entries were
`DENY`, and every response kept enforcement disabled. The full local report SHA-256
is `fca86339cfbb13c6327132318a197ed1eb0726f46de92c77e9b9236d8e6f9ee7`;
the path-independent evidence summary is committed under
`fixtures/benchmark/evidence/gate3-asm-pipeline-cuda-summary.json`.

During integration, the Rust event validator exposed that canonical BPF IDs
such as `evt:bpf:PID:SEQ:TIME` were rejected by the older single-segment ID
pattern. The schema and Rust validation now admit non-empty colon-delimited
event-ID segments while continuing to reject empty segments and unrelated
characters.

This is still a controlled-laboratory, single-checkpoint, dry-run result. No
seccomp, BPF-LSM, AppArmor, or other enforcement backend is called. A Gate 4
pilot remains conditional on a separately specified reversible denial/rollback
protocol. The measurements also show that per-event synchronous durable
persistence, rather than cache lookup, is now the common-path latency target.
