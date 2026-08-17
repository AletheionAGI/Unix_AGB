# Gate 4 live BPF Gate 3 protocol

Date: 2026-08-17

## Objective

Replace report 110's rebound trajectory with a newly executed controlled
trajectory captured from the exact process already running under the packaged
Gate 4 seccomp guardian. Feed the captured BPF events, without rewriting event
identity, subject, resource, time, provenance, or namespace, to the same frozen
three-member ASM-CM ensemble and Rust Gate 3 compiler.

No training or checkpoint selection is permitted. The package, checkpoints,
ASM source revision, 2-of-3 rule, disagreement action `abstain`, policy revision
`policy:bpf-observer-v1`, and deny-only authenticated cache contract remain
frozen from report 110.

## Pre-execution amendment

The first capture startup produced no artifact: bpftrace exposed non-UTF-8
bytes from an unrelated Unix-socket path and the observer rejected the run.
Before any valid corpus or model inference existed, inspection also established
that the current result-aware normalizer emits `policy:bpf-observer-v2`, whereas
report 110's replay carried v1. The observer is therefore hardened to preserve
such bytes with UTF-8 replacement in raw provenance, and this run aligns the
Gate 3 compiler and guardian cache configuration to
`policy:bpf-observer-v2`. Events will not be rewritten to imitate v1. All other
frozen inputs and criteria remain unchanged; the exact revision transition is
part of the evidence and report 110 is not reinterpreted.

## Controlled trajectory and selection

The protected workload performs a loopback connection, four benign config
reads, and one controlled credential-canary read, then remains alive in the
same PID. A system-wide BPF observer captures the execution. The corpus adapter
may select only events from the workload's exact namespace and stop at the
first event labeled `credential`; it may wrap these events in corpus metadata
but may not modify an event. Lost BPF events, sequence gaps, non-BPF provenance,
missing terminal evidence, or namespace mismatch invalidate the run.

The `malicious` label is controlled experimental ground truth, not an inference
from unusual activity and not a claim about natural telemetry. This one-case
corpus is not a security-efficacy benchmark and is not independently promotion
eligible.

## Frozen acceptance criteria

- all three ensemble members load the frozen hashes and no training occurs;
- 2-of-3 produces `DENY` from the new exact BPF trajectory with no required
  manual event mutation;
- Gate 3 emits a durable decision and one authenticated DENY-only cache entry
  for that same live namespace;
- a later external connect by the still-running protected process returns
  `EACCES`;
- an unprotected control does not return `EACCES`;
- authenticated empty rotation removes the restriction; and
- package purge leaves no AGB unit, account, listener, cgroup, policy, or
  installed path.

If every criterion passes, the live Gate 3 decision-integration mechanism in
promotion domain 1 is supported. Gate 4 as a whole remains a controlled
prototype; the other seven domains and natural unknown-attack efficacy remain
outside this verdict.
