# Gate 4 promotion protocol

Date: 2026-08-17

## Status and scientific boundary

Gate 4 remains a controlled exact-launch prototype. Report 105 supports its
narrow packaged mechanism; it does not satisfy this promotion protocol. This
protocol changes no Gate 2B result and does not reinterpret the Ubuntu 26.04
`grub2-common`/virtual-`fd0` degraded-boot observation.

The policy revision, package digest, inputs, thresholds, and expected negative
controls must be frozen before each promotion run. Missing, malformed,
unsigned, stale-revision, or partial evidence is a failure, never an implicit
pass. Every domain must report zero protected fail-open decisions and zero
effects on an out-of-scope control.

## Required evidence domains

1. `gate3_decision_integration`: an authenticated, unexpired, exact-revision
   compiled Gate 3 `DENY` activates enforcement; `ALLOW`, `ABSTAIN`, expired,
   corrupted, replayed, and wrong-revision inputs do not expand authority.
2. `real_application_coverage`: at least three opt-in real service/application
   classes, including a long-lived systemd service, pass functional positive
   controls while the declared controlled egress is denied.
3. `concurrency_endurance`: at least 32 simultaneous protected groups and an
   eight-hour run complete with zero fail-open, deadlock, leaked listener, or
   cross-group effect. Overload must remain bounded and scoped.
4. `authenticated_policy_lifecycle`: signed install, atomic revision rotation,
   rollback, replay rejection, and interrupted update preserve the last valid
   policy or terminate only the affected protected scope.
5. `failure_update_matrix`: worker, guardian, launcher, storage-full,
   read-only-storage, corrupt-state, package upgrade/downgrade, reboot, and
   kernel-notification failure paths have explicit, scoped outcomes.
6. `namespace_application_isolation`: concurrent PID, mount, user, network and
   cgroup namespace variants show no decision, descriptor, audit, or teardown
   leakage between applications.
7. `production_resource_latency`: under frozen nominal and overload profiles,
   CPU, RSS, listener count, audit growth and p50/p95/p99 latency remain within
   preregistered host-specific budgets. No percentile may be inferred from a
   truncated sample.
8. `ubuntu_boot_matrix`: the identical artifact passes Ubuntu 24.04 and 26.04
   install, enabled reboot recovery, upgrade, rollback and purge. Host-level
   degraded state is recorded separately; an AGB-related failed unit fails the
   domain, while an unrelated failure may only be delimited with journal and
   before/after evidence.

## Promotion rule

`supported: true` requires one or more authenticated successful evidence
records for every domain, all bound to the same frozen policy revision and
artifact digest, with zero protected fail-open and zero cross-scope effects.
The evaluator emits `gate4_status: controlled-prototype` until that condition
is met. A failed domain stays negative in the final report even if a later run
passes; the later run must be recorded as a new revision and evidence set.

## Execution order

Implement and validate Gate 3 decision binding first, then concurrent group
isolation, endurance/resource measurement, authenticated update/rollback,
failure injection, real application pilots, and finally the two-VM boot and
package matrix. Root/kernel tests run only in disposable VMs. No long GPU
training is part of this protocol.
