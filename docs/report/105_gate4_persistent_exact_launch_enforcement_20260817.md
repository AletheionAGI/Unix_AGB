# Gate 4 persistent exact-launch enforcement

Date: 2026-08-17

## Frozen artifact and scope

The report 104 protocol was executed with the reproducible package
`unix-agb-egress-guardian-lab_0.2.0_all.deb`, SHA-256
`43dd5ff9c1088c440851dd33312f700fcfc62f55f42743d64794532dd9813e9f`,
on Ubuntu 24.04.4 and Ubuntu 26.04. Two consecutive local builds produced the
same hash. Both VMs used policy revision
`policy:gate4-egress-guardian-v2`.

This is an opt-in exact-launch mechanism. It cannot attach seccomp to an
already-running arbitrary process. The root launcher creates a protected
process group, installs seccomp-user-notify before exec, and hands the listener
to the dedicated non-root guardian. The signed handoff binds peer credentials,
target PID, protected PGID, revision, expiry, and nonce. Unit tests reject
replay, stale revision, and invalid HMAC.

The guardian has no general `CAP_SYS_PTRACE`. Sockaddr bytes are requested
through a process-private adapter channel; the root ancestor opens only the
registered descendant's memory after exec and returns only the requested
bounded bytes. The audit record is appended, flushed, and fsynced before the
seccomp response.

## Enforcement and failure results

On both systems:

- the package remained disabled and inactive until explicit activation;
- loopback curl completed successfully;
- protected literal-IP external curl failed with `EACCES`;
- direct unregistered external curl completed successfully;
- a generation-1 worker crash retained the listener, started generation 2,
  and never released the protected external connect;
- exhausting the two-restart budget closed the adapter and terminated the
  protected process group with status 125 while an unrelated control remained
  active;
- stopping the guardian closed the adapter and terminated only the protected
  group; unrelated controls remained active;
- guest-driven reboot changed the boot ID and restored the enabled guardian;
- purge left no package, unit, account, process, listener, cgroup, policy key,
  configuration, state, runtime, or parent directory.

Guardian-death detection-to-kill/wait was 303 microseconds on Ubuntu 24.04 and
447 microseconds on Ubuntu 26.04, below the frozen 50 ms deadline. There were
zero observed protected fail-open decisions.

For the final 16 audited notifications, Ubuntu 24.04 measured 122 microseconds
p50 and 254 microseconds p95/p99. Ubuntu 26.04 measured 161 microseconds p50
and 5.130 milliseconds p95/p99. These small controlled samples include durable
append and fsync and are not production capacity measurements.

## Environmental negative result

After its final guest-driven reboot, Ubuntu 26.04 restored the guardian active
but `systemctl is-system-running` returned `degraded`. The only failed unit was
`grub2-common.service`; the journal recorded virtual floppy `fd0` I/O errors.
This is preserved as an environment-level negative result. It was unrelated to
the AGB package and remained visible after package purge. The report claims
guardian recovery, not a fully healthy Ubuntu 26.04 boot.

## Verdict and limitations

All report 104 criteria passed for the narrow declared scope, so the evidence
records `supported: true`. This supports only packaged, opt-in, exact-launch
laboratory enforcement. It does not support retroactive attachment, arbitrary
desktop application coverage, production concurrency or load, natural unknown
attack generalization, or system-wide deployment. Gate 4 remains a controlled
prototype, and Gate 2B v1/v4 negative results and v5 confirmation are unchanged.
