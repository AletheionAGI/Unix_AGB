# Gate 4 concurrent seccomp broker benchmark

Date: 2026-08-17

## Scope

This benchmark measures a disposable, process-local seccomp-user-notify path
from userspace receipt of a real `connect` notification through response
submission. It does not install a persistent broker or a system-wide policy.
The workload uses UDP `connect` against the documentation-only address
`198.51.100.1:443`; no payload is sent.

The benchmark binds the protected Python process by TGID, process start time,
resolved executable path, device, inode, and SHA-256. Eight target threads issue
256 concurrent connections in the normal case. An inherited Python subprocess
issues one identical connection as an out-of-scope isolation probe.

## Host result

The recorded host used Linux `7.0.0-29-generic`, x86-64, and Python 3.14.4.
The canonical local artifact is
`var/benchmark/gate4-egress-broker-benchmark.json`; its chart is
`var/benchmark/gate4-egress-broker-benchmark.png`.

In the normal 256-attempt scenario:

- all 256 target connections received `EACCES`;
- the inherited out-of-scope probe was allowed;
- zero notification IDs were invalid;
- response latency was 1.148 ms p50, 1.939 ms p95, and 2.366 ms p99;
- observed throughput was 4,986.25 responses/s.

The latency boundary starts when userspace receives the kernel notification and
ends when it submits the seccomp response. It therefore excludes time spent in
the kernel before userspace receipt. Throughput is specific to this host and
workload and is not a production-capacity claim.

## Bounded overload and degraded decisions

The overload scenario used 16 workload threads, one broker worker, a queue of
two, and a deterministic 5 ms adapter delay. Of 256 target responses, 237 took
the bounded overload path. All 256 target calls still received `EACCES`, while
the out-of-scope probe remained allowed. Observed latency was 0.019 ms p50,
5.337 ms p95, and 10.616 ms p99; immediate overload denials explain the low
median.

The one-millisecond timeout scenario injected a five-millisecond adapter delay.
All 64 target calls took the timeout fail-closed path and received `EACCES`.
The injected adapter-failure scenario also denied all 64 target calls. In both
cases, the inherited out-of-scope probe remained allowed. These are controlled
failure injections while the listener and response loop remain alive.

## Negative listener-loss result

Total listener loss did not satisfy the isolation or recovery requirement. The
broker closed its listener after receiving the first notification. On this
host, the notified workload made no progress for two seconds, so the watchdog
terminated the disposable process group. The inherited out-of-scope subprocess
was also disrupted because it inherited the seccomp filter.

This is a negative Gate 4 result and a promotion blocker. It must not be
described as a clean fail-closed response: no broker response was delivered,
the target did not receive a normal `EACCES` decision, and availability of an
out-of-scope descendant was not preserved. A persistent design needs an
explicit supervised lifecycle and recovery mechanism whose behavior is tested
without relying on listener destruction.

## Interpretation

The live-listener result supports bounded concurrency, overload, timeout,
adapter-failure, and exact-scope behavior inside this disposable laboratory
boundary. It does not promote Gate 4. Persistent lifecycle, authenticated
policy distribution, restart/recovery behavior, and a safe listener-loss design
remain outstanding. No neural inference or external service is in the hot path.

Reproduce the benchmark and chart with:

```sh
make benchmark-gate4-egress-broker
make plot-gate4-egress-broker
```
