# Gate 4 policy-worker recovery with retained listener

Date: 2026-08-17

## Objective

Report 94 found that closing the last seccomp user-notification listener caused
the disposable protected group to stall until a watchdog terminated it. An
inherited out-of-scope subprocess was also disrupted. This increment does not
reinterpret that negative result. Instead, it narrows the recoverable failure
boundary.

The listener and deterministic enforcement fallback now remain in a minimal
supervisor. An optional policy worker runs in a replaceable subprocess. A
worker crash, malformed response, broken channel, or response timeout cannot
destroy the listener. For an exact protected target, the in-flight decision
falls back to `DENY`; an out-of-scope request bypasses the worker and remains
`ALLOW`. The supervisor starts a new worker generation before accepting the
next policy-backed decision.

## Implementation checks

The policy worker communicates with the supervisor over a local
`SOCK_SEQPACKET` socket pair. Tests verify that:

- an injected worker exit makes the in-flight target decision fail closed;
- the generation number advances exactly once;
- the next target decision is served by the replacement worker;
- an out-of-scope request never reaches or restarts the policy worker;
- inherited socket endpoints are closed on the correct side of `fork`, so a
  worker exit produces immediate EOF instead of an artificial 50 ms timeout.

The listener supervisor remains the trusted enforcement component. This is not
a general broker high-availability claim.

## Real seccomp result

The extended concurrent benchmark injected one real policy-worker process exit
during 64 protected UDP `connect` attempts. The address was the
documentation-only `198.51.100.1:443`, and no payload was sent.

- all 64 protected calls received `EACCES`;
- the in-flight crash decision used the scoped fail-closed fallback;
- exactly one worker restart was recorded;
- later decisions used worker generation 2;
- the inherited out-of-scope probe remained allowed;
- zero seccomp notification IDs were invalid;
- response latency was 1.276 ms p50, 4.081 ms p95, and 4.396 ms p99;
- observed throughput was 3,858.82 responses/s.

The benchmark artifact remains local at
`var/benchmark/gate4-egress-broker-benchmark.json`, with the corresponding PNG
at `var/benchmark/gate4-egress-broker-benchmark.png`. These figures are specific
to Linux `7.0.0-29-generic`, x86-64, Python 3.14.4, and this workload.

## Preserved blocker

The listener-loss scenario still stalls until the two-second watchdog and does
not preserve the inherited out-of-scope subprocess. Worker recovery therefore
solves only the replaceable policy-process failure. It does not solve failure
of the listener-owning supervisor, host shutdown, or recovery after supervisor
restart.

A persistent design must keep the supervisor small, avoid optional inference
in its response path, supervise the complete protected cgroup or service, and
define teardown/restart behavior before installing filters. Gate 4 remains a
laboratory prototype.
