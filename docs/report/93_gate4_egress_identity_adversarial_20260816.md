# Gate 4 egress identity adversarial validation

This increment hardens the disposable seccomp-user-notify egress pilot without
installing a persistent or system-wide policy.

## Scope binding

The protected target is released into `exec` only after the broker receives its
PID and freezes the expected executable artifact. The first notification binds
the target process to TGID, process start time, resolved executable path,
filesystem device/inode, and SHA-256. Later notifications revalidate TGID,
start time, path, device, and inode. SHA-256 is computed at binding rather than
on every syscall.

Using TGID is essential: the real curl run generated notifications from both
the leader and another thread. An intermediate implementation compared the
notification TID directly with the leader PID and therefore treated some curl
threads as out of scope. That bypass was found by the live pilot and corrected
before this report.

## Notification and failure safety

Every seccomp notification ID is validated with
`SECCOMP_IOCTL_NOTIF_ID_VALID` after receipt and again immediately before the
response. Stale IDs receive no response or decision. The completed run observed
zero invalid IDs and zero stale wakeups.

Adapter failure, decision timeout, overload, or policy abstention maps to
`DENY` only for the frozen target process. The same conditions map to `ALLOW`
for an inherited but out-of-scope process. Unit tests cover PID reuse, inode and
content replacement, symlink resolution, timeout, adapter crash, overload, and
out-of-scope fallback.

## Real isolation result

Each loopback and external case also ran an inherited `/usr/bin/python3.14` UDP
connect to the documentation-only address `198.51.100.1:443`. UDP `connect`
selects a peer without sending payload. The broker recorded
`EXECUTABLE_OUT_OF_SCOPE`, `ALLOW`, and `enforcement_applied: false` in both
cases.

For the protected curl, Unix sockets, the local resolver, and loopback remained
allowed. All decoded external curl destinations and scoped unresolved
destinations received `EACCES`; the external curl exited 7. Ten scoped denials
were applied. The maximum observed decision time in this run was below 1 ms,
well below the 100 ms fail-closed deadline. This is functional evidence, not a
formal latency benchmark.

The current artifact is `var/benchmark/gate4-curl-egress-pilot.json`. It records
`system_wide_changes: false`; process exit destroys the filter and listener.
