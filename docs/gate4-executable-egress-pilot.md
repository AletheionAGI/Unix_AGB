# Gate 4 executable-scoped egress pilot

This pilot installs a seccomp-user-notify filter only in a disposable
`/usr/bin/curl` process tree. It does not install nftables, AppArmor, systemd,
or system-wide rules.

The deterministic policy permits Unix sockets and loopback, denies a decoded
external IPv4/IPv6 destination, and fails closed when a destination for the
scoped executable cannot be decoded. The broker returns `EACCES` before the
external `connect` is executed. Process exit destroys the filter and listener.

Run outside an enclosing sandbox that already denies `connect` with seccomp:

```sh
make gate4-egress-seccomp-pilot
```

Success requires all of the following in
`var/benchmark/gate4-curl-egress-pilot.json`:

- loopback curl exits zero and has no denied notification;
- external curl exits nonzero;
- at least one decoded external destination has `effect: DENY`;
- the denial records `errno: 13` and `enforcement_applied: true`;
- `system_wide_changes` is false.

An outer seccomp profile has higher precedence than an inner user-notification
filter when it returns an error action. In that environment the inner listener
receives no valid notification, so an ordinary connection failure is not
accepted as AGB enforcement evidence.
