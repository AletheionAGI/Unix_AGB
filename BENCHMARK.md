# Unix-AGB Benchmark Protocol

Status: Gate 0 draft
Mode: audit-only

## Research question

Does persistent trajectory state improve classification of controlled security
sequences over event-local and conventional temporal baselines without
unacceptable resource cost, false positives, or namespace leakage?

## Frozen modes

| Mode | Description |
|---|---|
| A | event-local static rules |
| B | deterministic sequence rules |
| C | sliding-window counters / conventional risk score |
| D | fake or real ASM-CM state without evidence retrieval |
| E | ASM-CM state plus authorized canonical evidence and explicit policy |

## Initial workload

- 20 controlled benign trajectories;
- 20 controlled malicious trajectories;
- shared individual operations in different order or provenance contexts;
- at least three deterministic workload seeds;
- independent namespace and PID-reuse cases;
- replay, duplicate, malformed, and event-gap cases.

The first frozen controlled corpus is
`fixtures/benchmark/gate2-v1.json`. Run `make benchmark-gate2` to expand its
three fixed seeds into 20 benign and 20 malicious trajectories and write the
machine-readable report to `var/benchmark/gate2-v1-report.json`. Every mode
receives the same expanded events. The report includes a manifest digest,
terminal-decision digests, confusion matrices, latency percentiles, Python peak
allocation, snapshot size, and recovery proofs.

Mode D currently uses `D:stateful-proxy`, a deterministic persistent adapter.
It validates the process and persistence boundary but is not Mode D's eventual
ASM-CM implementation. Gate 2 cannot be promoted from proxy results.

The optional `make benchmark-gate2-asm-cm` replaces only Mode D with the real
durable fast-weight ASM-CM adapter. It requires explicit checkpoint SHA-256 and
ASM source revision inputs, records both in the report, and keeps the neural
state outside the Rust gateway process. ASM-CM selects canonical evidence IDs;
the deterministic Unix-AGB policy remains responsible for the final effect.

The adversarial multi-seed protocol is frozen in
`fixtures/benchmark/gate2-adversarial-v2.json` and executed with
`make benchmark-gate2-multiseed`. It contains 60 balanced trajectories across
clean, trusted-network, risk-then-reset, long-gap risk, trusted-then-risk, and
repeated-risk families. Each malicious relation is separated from the terminal
credential access by 8–24 distractors. Promotion requires every ASM-CM seed to
be non-inferior to the strong sequence baseline and at least two seeds to
strictly exceed its accuracy. A perfect sequence baseline therefore blocks an
unsupported superiority claim even when ASM-CM is also perfect.

The Gate 0 synthetic generator is plumbing evidence only. It is not a detection
benchmark and cannot support security efficacy claims.

## Minimal causal proof

`fixtures/events/causal-pair.jsonl` freezes two namespaces with an identical
terminal operation and resource but different preceding histories. Run:

```bash
make causal-proof
```

The executable rejects the experiment unless the terminal actions are equal,
the benign trajectory produces shadow `ALLOW`, and the exec → network →
credential trajectory produces shadow `DENY`. Both enforcement records must
remain `applied: false`. This demonstrates deterministic trajectory-dependent
policy behavior in the fake state engine; it does not demonstrate learned
causal inference, real kernel blocking, or security efficacy on natural data.

## Live laboratory slice

With Rust, `strace`, and Landlock available, run:

```bash
make live-proof
```

This launches two real workloads and writes `var/live-proof/REPORT.json`.
The benign workload reads local configuration before the terminal secret; the
suspicious workload connects to a loopback laboratory listener. Both request
the same secret path. The gateway emits shadow `ALLOW`/`DENY`, and the workload
applies the latter through a process-local Landlock ruleset. The report keeps
trace hashes, event IDs, and the observed kernel `EACCES`. Because authorization
is cooperative and observation uses `strace`, this remains laboratory evidence
and is not Gate 1 production telemetry.

## Metrics

- precision, recall, and false positives per hour;
- time-to-detect and time-to-policy-publication;
- ingest throughput and dropped/rejected events;
- p50/p95/p99 append and state-update latency;
- p50/p95/p99 cached enforcement latency when Gate 4 exists;
- CPU, RSS, optional VRAM, bytes of state per namespace;
- canonical storage bytes per event;
- restart recovery and replay behavior;
- cross-namespace violation count;
- evidence completeness and operator reversal rate.

## Accounting rules

Report separately:

```text
retained causal state
snapshot bytes
canonical event storage
process RSS
accelerator memory
reader evidence/context
```

Do not present the earlier ASM-CM ~140 KiB component measurement as a Unix-AGB
result. Every configuration must be measured independently.

## Promotion gate

Automatic enforcement remains prohibited until a frozen protocol demonstrates:

- acceptable false positives for the chosen workload;
- bounded resource use;
- reliable restart and rollback;
- safe fallback to base policy;
- complete provenance for critical decisions;
- no observed cross-namespace leakage in the defined adversarial suite;
- measurable value over strong non-neural baselines.

## Reproducibility record

Each published run must include commit SHA, schemas, configuration fingerprint,
workload manifest, seed, hardware, OS/kernel version, dependency lockfiles, raw
events, decisions, resource measurements, and an explicit limitations section.
