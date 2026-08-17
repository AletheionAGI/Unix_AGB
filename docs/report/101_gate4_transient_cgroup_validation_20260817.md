# Gate 4 transient cgroup validation

Date: 2026-08-17

## Scope

This proof validates the reversible Gate 4 mechanisms inside real cgroup v2
boundaries managed by transient user-systemd services. It does not install,
enable, or persist the packaging scaffold from report 100.

Two uniquely named transient units were created with `systemd-run --user`. The
first executed the real in-flight seccomp recovery proof from report 97. The
second held a disposable launcher, guardian, and broker process tree for cgroup
membership and failure teardown. A control process remained outside both
units.

## Result

The host used Linux `7.0.0-29-generic` and cgroup v2.

- the complete seccomp in-flight recovery proof passed inside its transient
  unit, including 64 target denials, out-of-scope allowance, notification-ID
  validation, lease recovery, and broker replacement;
- launcher, guardian, and broker all reported the exact ControlGroup returned
  by systemd;
- after the injected guardian exit, the launcher applied the formal 50 ms
  deadline;
- direct `cgroup.kill` was writable and used successfully;
- teardown was issued after 50.221 ms;
- the external control process remained alive;
- both transient units reached `LoadState=not-found` after collection;
- no system-wide configuration or persistent unit was changed.

The artifact is `var/benchmark/gate4-transient-cgroup.json`. The nested seccomp
artifact is `var/benchmark/gate4-transient-cgroup-seccomp.json`.

## Interpretation

This replaces the process-group approximation for the tested teardown boundary
with a real delegated user cgroup. It establishes that `cgroup.kill` affects the
defined transient unit while leaving an unrelated process alive on this host.
It does not validate a privileged system service, reboot recovery, package
installation, or uninstall rollback.

The next safe environment is a disposable Ubuntu VM. There, the inactive
packaging scaffold can be built into a package, installed with dedicated
accounts and delegated system cgroups, exercised across reboot, then removed
while verifying that no unit, account, listener, cgroup, or policy artifact
remains.

Reproduce without installation using:

```sh
make gate4-transient-cgroup
```
