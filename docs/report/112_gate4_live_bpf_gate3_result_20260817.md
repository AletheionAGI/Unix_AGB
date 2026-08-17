# Gate 4 live BPF Gate 3 result

Date: 2026-08-17

## Result

Report 111 was executed on the disposable Ubuntu 24.04.4 VM with package
0.3.1 (SHA-256 `a14a3d...c00`), the three frozen Gate 2B v5 checkpoints, and
ASM revision `4c8eddf2f07d9aec800769323d7e1effbd64815a`. No training occurred.

The successful capture contained 397 system-wide normalized events with zero
lost events. Exact-namespace selection retained 12 newly captured BPF events
from the protected PID through its controlled credential-canary read: process
execution, library reads, socket creation, loopback connection, four distractor
reads, and the terminal read. No selected event object was rewritten. The
single-case corpus remains `promotion_eligible: false`; its controlled label is
not evidence about natural unknown attacks.

The current result-aware normalizer emitted `policy:bpf-observer-v2`. As
pre-execution report 111 records, the compiler and guardian configuration were
aligned to v2 rather than rewriting the new events to report 110's v1. The
frozen ensemble produced 11 `ALLOW` decisions and one unanimous `DENY`, with
three member inferences and zero disagreement. The Rust compiler wrote 12
durable decisions and one authenticated deny-only cache entry.

Atomic publication changed the next external connection by the still-running
protected PID to `EACCES`. An unprotected control reached the same private
gateway and returned `ECONNREFUSED`. Authenticated empty rotation then made the
same protected PID return `ECONNREFUSED`. The guardian's exact-namespace audit
contains 58 records (57 allow, one deny); latency was 252.5 microseconds p50,
317 microseconds p95, 377 microseconds p99, and 493 microseconds maximum. Purge
left no package, unit, account, process, listener, cgroup, configuration,
state, or installed path.

## Rejected attempts retained as engineering findings

No failed attempt contributes to the positive result. One capture was rejected
before artifact creation because an unrelated Unix-socket path contained
non-UTF-8 bytes; the observer now preserves such raw bytes with replacement.
A later valid capture outlived the launcher's five-second silence watchdog, and
an early recovery attempt hit `ADAPTER_FAILURE` after the same timeout. The
final workload used audited loopback heartbeats during model inference and
rotation, then completed the full transition in one PID. These findings expose
the launcher silence timeout as a production design constraint.

## Verdict

`live_bpf_chain_supported: true` and
`report_110_replay_limitation_removed: true`. New physical BPF telemetry from
the already-supervised service drove the frozen model, state, compiler,
authenticated cache, guardian, and kernel denial without a protected fail-open
or cross-scope effect.

`first_promotion_domain_supported: false`. Report 106 additionally requires
`ALLOW`, `ABSTAIN`, expired, corrupted, replayed, and wrong-revision negative
inputs under one frozen artifact/revision plus authenticated promotion
evidence. Prior v1 runs cannot silently be combined with this v2 run. Gate 4
therefore remains `controlled-prototype`. Gate 2B v1/v4 negative results and
the v5 synthetic confirmation are unchanged.
