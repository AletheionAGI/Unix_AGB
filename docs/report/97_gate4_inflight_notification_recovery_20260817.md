# Gate 4 in-flight seccomp notification recovery

Date: 2026-08-17

## Objective

Report 96 demonstrated listener handoff after a broker exited between completed
notifications. It explicitly left one question open: what happens if the
broker completes `SECCOMP_IOCTL_NOTIF_RECV` and dies before
`SECCOMP_IOCTL_NOTIF_SEND`?

This proof adds a guardian-visible notification lease. Immediately after
`RECV`, and before optional policy work, the broker sends the notification ID
and notified TID over its private `SOCK_SEQPACKET` control channel. The guardian
retains the original listener descriptor. If the broker exits with a lease in
flight, the guardian validates the notification ID against the kernel,
independently maps the notified TID to its TGID, applies the exact-process
fallback, and only then starts the replacement generation.

An invalid ID is never answered. If process identity cannot be resolved, the
guardian also sends no response; a persistent implementation must escalate that
case to bounded protected-group teardown.

## Injected failure

Generation 1 deliberately exited with status 71 after receiving its eighth
notification and publishing its lease, but before sending a seccomp response.
The guardian did not rely on a target boolean supplied by the failed broker. It
recomputed the TGID and compared it with the frozen protected process identity.

The in-flight notification remained valid on the retained listener. The
guardian returned `EACCES` for that exact target notification, started broker
generation 2, and the workload continued without teardown or watchdog action.

## Host result

The run used Linux `7.0.0-29-generic`, x86-64, and Python 3.14.4. Eight threads
issued 256 UDP `connect` calls to the documentation-only address
`198.51.100.1:443`; no payload was sent.

- the crash occurred after `RECV` and before `SEND` as declared;
- the leased notification was still kernel-valid;
- the guardian's validation and fail-closed response took 123 µs;
- generation 2 became ready in 9.839 ms;
- all 256 protected calls received `EACCES`;
- the inherited out-of-scope probe remained allowed;
- the workload completed without teardown;
- zero notification IDs were invalid;
- ordinary broker decision latency was 46 µs p50, 50 µs p95, and 73 µs p99.

The local artifact is `var/benchmark/gate4-inflight-recovery.json`. Measurements
are specific to this host and workload.

## Security boundary and limitations

The lease contains no `sockaddr` or policy evidence. The recovery decision uses
only a kernel-valid notification ID and independently resolved exact process
identity. The tested deterministic fallback is `DENY` for the protected TGID
and `CONTINUE` for a verified out-of-scope TGID.

Recovery depends on the broker publishing the lease before optional work. A
crash inside the tiny interval between kernel `RECV` completion and lease
publication is not covered. The guardian remains a trusted single point of
failure, and the control channel is not yet an authenticated persistent-service
protocol. Gate 4 therefore remains a laboratory prototype.

Next promotion work is to eliminate or bound the pre-lease interval, bind the
handoff to authenticated peer credentials and policy revision, rate-limit
restart loops, and test guardian failure with explicit protected-cgroup
teardown.

Reproduce with:

```sh
make gate4-inflight-recovery
```
