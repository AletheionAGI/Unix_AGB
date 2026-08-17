# Gate 4 automated campaign runner protocol

Date: 2026-08-17

## Objective

Provide one local, unattended runner for the coordinated Gate 4 campaign. The
runner must consume no model/API service during its waiting period and must
continue correctly after the interactive Codex session closes.

The campaign targets `real_application_coverage`, `concurrency_endurance`,
`namespace_application_isolation`, `production_resource_latency`, and
`ubuntu_boot_matrix`. Each domain retains separate acceptance criteria and
signed evidence; sharing a runner does not merge their verdicts.

## Fail-closed execution contract

The runner consumes a frozen JSON manifest containing the package digest,
policy revision, exact argv arrays, workload classes, probes, teardown commands
and artifact paths. It never evaluates a shell string. Formal mode refuses:

- a duration below 28,800 seconds;
- fewer than 32 simultaneous workload groups;
- fewer than three declared real application classes;
- omission of the five targeted domains; or
- an invalid package or policy-revision identifier.

Before setup, the runner reads the declared package path and requires its
computed SHA-256 to equal the frozen artifact digest. A missing or changed
package prevents campaign startup.

Smoke mode exists only to validate orchestration and cannot become promotion
evidence.

The repository includes a default smoke manifest so `make gate4-campaign`
works without environment configuration. Its three `sleep` processes are
orchestration fixtures, not real-application evidence. A formal manifest must
be supplied explicitly and still satisfies all formal validation gates.

Setup commands run sequentially. Workloads start concurrently and must remain
alive unless their manifest entry explicitly permits clean early completion.
At every interval the runner records monotonic and wall time, a chained
heartbeat digest, host load, per-process CPU ticks, RSS and descriptor count,
and exact probe return codes/output hashes. Nonzero setup/probe/teardown status,
unexpected workload death, signal interruption, metric read failure, missing
artifact or hash mismatch is preserved as a failure.

Teardown always runs in a `finally` path. The final summary is written
atomically and includes the manifest digest, heartbeat-chain head, counts,
resource maxima, process outcomes, failures, artifact SHA-256 values, elapsed
duration and a `complete` flag. A truncated run is never summarized as formal
success.

## Scientific boundary

The runner provides trustworthy orchestration evidence; it does not itself
prove that a domain passed. Domain evaluators consume the completed artifacts
and emit independent authenticated evidence. The formal eight-hour duration is
real elapsed monotonic time and cannot be accelerated or inferred from a smoke
run.
