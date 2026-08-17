# Gate 4 Ubuntu package lifecycle

Date: 2026-08-17

## Scope

This experiment built and installed the opt-in
`unix-agb-egress-guardian-lab_0.1.0_all.deb` package in a disposable Ubuntu
26.04 LTS Multipass VM. It tested default inactivity, explicit activation,
boot recovery, and complete purge. The package runtime exposes a local health
socket and records its exact policy revision. It explicitly reports
`enforcement_active: false`; it does not install a persistent seccomp filter.

The package SHA-256 was
`b63e9950ac3f1c6053f34f2444efaa2f70197066e93c909c56b505d51fed2f0a`.
The VM used image prefix `9dc7c5363c01`, kernel `7.0.0-28-generic`, systemd
`259.5-0ubuntu3`, and the pre-install snapshot `clean-base`.

## Results

Installation created the dedicated `unix-agb-guardian` identity but left the
unit disabled and inactive. No activation marker existed. `systemd-analyze
verify` accepted the package unit; unrelated Ubuntu XFS units emitted ignored
CPUAccounting warnings.

The first explicit start exposed a real packaging race: an `ExecStartPost=test
-S` check ran before Python bound the socket, killed the otherwise healthy
daemon, and exhausted the three-start budget. The synchronous check was
removed. The rebuilt package then became active, published a `ready` state,
and answered its Unix health socket under UID 104 and GID 109.

The guest boot identity changed from
`b86494b1-8e56-440b-827f-835be6c52233` to
`f58a7a85-f90e-4d69-bb89-4e10a18405ab`. After the recovered cold boot, the
unit was enabled and active with a new PID, the socket answered, and the state
retained `policy:gate4-egress-guardian-v1` with enforcement disabled.

The graceful `multipass restart` result was negative. The guest emitted a real
QEMU RESET, reacquired DHCP, and exposed TCP/22, but Multipass 1.16.3 remained
in `Restarting`. A forced instance stop/start also left the client in
`Starting`; `multipassd` required SIGKILL and service restart. This is recorded
as a Multipass lifecycle failure. The subsequent cold-boot service recovery
must not be reinterpreted as successful graceful reboot recovery.

`dpkg --purge` then removed the package. The independent cleanup audit found:

- no dpkg package record;
- no unit or enablement link;
- no dedicated user or group;
- no guardian process or Unix listener;
- no matching cgroup;
- no configuration, marker, runtime, state, documentation, or socket path.

All 111 Python tests and 14 Rust tests passed outside the executor's
socket-restricted sandbox. The repository summary evidence is
`fixtures/benchmark/evidence/gate4-package-lifecycle-summary.json`.

## Verdict and limitations

The disabled-by-default Debian lifecycle, explicit activation, cold-boot
recovery, and purge rollback are supported for this laboratory runtime. The
overall confirmation remains negative (`supported: false`) because graceful
reboot did not complete and the packaged runtime intentionally performs no
persistent enforcement. This does not promote Gate 4 and does not alter any
Gate 2B v1, v4, or v5 result.
