# Gate 4 persistent packaging scaffold

Date: 2026-08-17

The repository now contains an opt-in systemd packaging scaffold for the future
egress guardian. It is deliberately not installed, enabled, or started.

The unit requires `/etc/unix-agb/egress-guardian.enabled`, runs under a dedicated
identity, uses `KillMode=control-group`, limits restart bursts, and declares
filesystem, device, privilege, address-family, and kernel hardening. The example
configuration is disabled, laboratory-only, revision-bound, and has no
protected cgroup. The install manifest explicitly records
`installed_by_this_repository: false` and names the runtime executable as not
yet promoted.

`systemd-analyze verify` accepted the unit syntax on the development host. The
Python runtime module remains intentionally absent from the install manifest's
promoted files, so syntax validation must not be interpreted as service
readiness.

This is packaging validation, not a persistent enforcement deployment. The
runtime path `/usr/libexec/unix-agb/agb-egress-guardian` intentionally does not
become installable until delegated-cgroup ownership, authenticated runtime
handoff, recovery boot, uninstall rollback, and distribution packaging are
validated on a disposable Ubuntu host.
