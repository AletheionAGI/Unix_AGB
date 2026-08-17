# Gate 4 retained-listener guardian handoff

Date: 2026-08-17

## Objective

Report 94 preserved a negative result: closing the final seccomp notification
listener stalled the protected process group and disrupted an inherited
out-of-scope subprocess. Report 95 recovered an optional policy-worker crash
while a trusted supervisor retained the listener. This proof tests the next
narrower architecture: a guardian retains the original listener while a
replaceable broker generation receives a duplicate over `SCM_RIGHTS`.

The proof is disposable and process-local. It does not install a service,
system policy, or persistent filter.

## Handoff boundary

The guardian starts broker generation 1, sends one listener descriptor over a
private `SOCK_SEQPACKET` channel, and waits for an explicit ready message. The
broker closes the listener descriptor inherited through `fork` before using
the descriptor received through `SCM_RIGHTS`; therefore the exercised path is
the explicit handoff rather than accidental descriptor inheritance.

Generation 1 exits deliberately after eight completed responses. The guardian
retains its listener, verifies exit status 70, creates generation 2, transfers
a new duplicate of the same listener, and waits for readiness. Notifications
queued during that interval remain attached to the retained listener.

This proof uses a preregistered deterministic rule: the exact protected process
cannot use external networking, while other TGIDs are allowed. A sibling broker
cannot read the protected process's `sockaddr` through `/proc/<tid>/mem` under
the host Yama policy. The proof does not weaken `ptrace` restrictions and does
not claim destination decoding in this topology. Destination-aware enforcement
remains demonstrated only in the parent-supervisor pilots.

## Host result

The run used Linux `7.0.0-29-generic`, x86-64, and Python 3.14.4. Eight threads
issued 256 UDP `connect` calls to the documentation-only address
`198.51.100.1:443`; no payload was sent.

- generation 1 exited after eight completed responses;
- generation 2 became ready using a newly transferred listener descriptor;
- handoff/replacement readiness took 9.701 ms;
- all 256 target connections received `EACCES`;
- the inherited out-of-scope probe was allowed;
- the workload completed without watchdog intervention;
- zero notification IDs were invalid;
- decision latency was 44 µs p50, 49 µs p95, and 68 µs p99.

The local artifact is `var/benchmark/gate4-listener-guardian.json`. These
measurements are host- and workload-specific and are not production capacity or
availability claims.

## Interpretation and remaining blocker

Retaining the listener across broker generations avoids the total-listener-loss
failure from report 94 for the tested between-notification crash. It does not
prove recovery if a broker dies after receiving a notification but before
responding, nor does it remove the guardian as a trusted single point of
failure. The local handoff channel is process-private but is not yet an
authenticated persistent-service protocol.

Gate 4 remains a laboratory prototype. Promotion still requires in-flight
notification crash testing, authenticated peer identity and revision binding,
bounded restart policy, protected-cgroup teardown when the guardian fails, and
clean service restart/recovery tests.

Reproduce with:

```sh
make gate4-listener-guardian
```
