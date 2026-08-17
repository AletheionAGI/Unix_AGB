# Gate 4 Ubuntu 24.04 package lifecycle

Date: 2026-08-17

## Scope

This compatibility run repeated report 102's lifecycle matrix on a fresh
Ubuntu 24.04.4 LTS Multipass VM. It used the exact same
`unix-agb-egress-guardian-lab_0.1.0_all.deb` artifact with SHA-256
`b63e9950ac3f1c6053f34f2444efaa2f70197066e93c909c56b505d51fed2f0a`.
The VM image prefix was `6e40c07ae715`, with kernel `6.8.0-137-generic` and
systemd `255.4-1ubuntu8.17`. Snapshot `clean-base` was taken before package
installation.

The runtime remained lifecycle-only and continued to report
`enforcement_active: false`. No persistent seccomp enforcement was installed
or evaluated.

## Results

Package installation created UID 109 and GID 112 for
`unix-agb-guardian`. The unit was disabled and inactive, and the activation
marker was absent. The systemd unit verified successfully. After explicit
configuration and marker activation, the service became active, published its
ready state, and answered the local Unix health socket with exact policy
revision `policy:gate4-egress-guardian-v1`.

The guest was rebooted directly through `systemctl reboot`, avoiding the
Multipass 1.16.3 `restart` control path that failed in report 102. The boot ID
changed from `ae7df655-075c-41f4-b8b7-c730f712393c` to
`3fd672e6-88cf-4dc5-a056-6644bdec94cd`. After reboot, systemd reported
`running`, the unit remained enabled and active under a new PID, and the health
socket returned the expected revision with enforcement disabled.

After `dpkg --purge`, the hardened cleanup audit found no package record,
unit, enablement link, account, process, Unix listener, cgroup, file, or parent
directory. All seven cleanup criteria passed.

## Verdict and limitations

The scoped disabled-by-default package lifecycle, graceful guest reboot
recovery, and residue-free purge are supported on Ubuntu 24.04.4 LTS. The
summary records `lifecycle_supported: true` but retains overall
`supported: false`, because the packaged runtime intentionally does not enforce
egress policy. The successful guest-driven reboot does not erase report 102's
negative Multipass `restart` result on Ubuntu 26.04.
