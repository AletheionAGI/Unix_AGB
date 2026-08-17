# Gate 4 persistent enforcement protocol

Date: 2026-08-17

## Frozen scope

This experiment promotes no model and changes no Gate 2B result. It tests one
opt-in, exact-launch egress policy in disposable Ubuntu 24.04 and 26.04 VMs.
The packaged launcher creates the protected process tree; seccomp cannot be
attached retroactively to arbitrary existing processes.

The policy is fixed before execution:

- allow AF_UNIX and IPv4/IPv6 loopback connects;
- deny non-loopback IPv4/IPv6 connects with `EACCES`;
- continue notifications from a process outside the registered target tree;
- never convert decode, identity, timeout, handoff, or worker failure into
  silent allow for the protected target.

## Boundaries

The launcher installs seccomp-user-notify before executing the workload and
passes the listener to the persistent guardian with `SCM_RIGHTS`. It also opens
only the protected child's `/proc/<pid>/mem` while parent-child ptrace rules
permit it and passes that already-scoped descriptor. The guardian must not gain
general `CAP_SYS_PTRACE` or unrestricted process-memory access.

The handoff is bound to Unix peer credentials, exact policy revision,
target PID, cgroup/process-group identity, nonce, monotonic expiry, and
HMAC-SHA-256. Replays, stale revisions, unexpected peers, missing descriptors,
and malformed messages are rejected.

The guardian retains the listener while a replaceable policy worker handles
decisions. A worker crash has a bounded restart budget. An unresolved in-flight
notification is denied when its kernel ID and target identity remain valid. A
pre-lease or guardian failure has a 50 ms recovery deadline followed by scoped
termination of only the registered protected group.

## Frozen tests

Both distributions must run the same package hash and configuration revision.
Each VM must demonstrate:

1. package and service disabled by default;
2. authenticated exact-revision listener handoff;
3. loopback curl succeeds;
4. external literal-IP curl fails with `EACCES`;
5. an unregistered control process retains external networking;
6. injected worker death recovers without releasing a protected connect;
7. exhausted restart budget terminates only the protected group;
8. guardian death terminates only the protected group within the deadline;
9. guest-driven reboot restores the enabled guardian fail-closed;
10. p50/p95/p99 notification and recovery latency are recorded;
11. purge leaves no package, unit, account, process, listener, cgroup, policy,
    configuration, state, or runtime path.

Any failed item remains negative. Cold boot does not substitute for graceful
reboot. A lifecycle-only health response does not satisfy enforcement.

## Promotion rule

`supported: true` requires all eleven criteria on both Ubuntu versions, zero
protected fail-open decisions, zero impact on the unregistered control, and a
complete purge audit. Passing this experiment supports only the narrow
exact-launch laboratory mechanism; it does not establish safe attachment to
arbitrary applications or production readiness.
