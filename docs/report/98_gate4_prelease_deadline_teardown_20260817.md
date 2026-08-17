# Gate 4 pre-lease deadline and scoped teardown

Date: 2026-08-17

Generation 1 was terminated after its eighth seccomp `RECV` and before it could
publish the notification lease. The guardian retained the listener and made
generation 2 ready in 9.663 ms, but the unknown in-flight notification could
not be identified safely.

A formal 50 ms recovery deadline was therefore applied. At expiry, the launcher
sent `SIGTERM` only to the disposable protected process group, waited 20 ms,
and escalated that group to `SIGKILL`. A separately created control process
outside the group remained alive. No system-wide policy or persistent service
was installed.

The proof recorded 58 completed decisions before teardown. This does not mean
the pre-lease notification was recovered: it was not. Terminating the protected
group is the deliberately destructive fail-safe for this unrecoverable state.
The process-group boundary is laboratory-only; a production implementation
requires a delegated cgroup with exact ownership.

Artifact: `var/benchmark/gate4-prelease-teardown.json`.

Reproduce with `make gate4-prelease-teardown`.
