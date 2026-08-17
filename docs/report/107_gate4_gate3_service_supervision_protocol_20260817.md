# Gate 4 Gate 3 service-supervision protocol

Date: 2026-08-17

## Frozen objective

This experiment adds a new opt-in mode without rewriting the frozen report 105
artifact or its result. A protected service is launched with seccomp user
notification installed before `exec`. The guardian may deny a later external
`network.connect` only when the current authenticated Gate 3 cache contains an
unexpired `DENY` for the service's exact process namespace.

The first implementation maps an active trajectory-level Gate 3 network deny
to external-egress containment for that exact namespace. Loopback and Unix
sockets remain allowed. This broader containment mapping is explicit; it must
not be described as destination-specific enforcement because the compiled
Gate 3 v1 cache stores a resource digest, not the normalized destination.

## Required behavior

- The launcher derives the same boot-ID, PID and start-time namespace identity
  used by the BPF normalizer and binds it into the authenticated handoff.
- The guardian accepts only Gate 3 cache format 1, exact revision, HMAC-SHA-256,
  `DENY`-only entries and valid state/expiry fields.
- Initial missing, corrupt or unauthenticated policy prevents activation.
- Reload is atomic: a corrupt replacement never erases the last authenticated
  snapshot. An authenticated empty snapshot or expiry removes the restriction.
- No matching active Gate 3 deny allows the intercepted syscall to continue;
  `ALLOW` and `ABSTAIN` never compile into this cache.
- Matching external egress is durably audited before `EACCES`; loopback remains
  available; another namespace remains unaffected.
- Guardian or adapter failure retains the existing scoped teardown behavior and
  never converts an active matched denial into silent allow.
- Launcher startup waits at most two seconds for the guardian control socket;
  readiness timeout fails the launch before the protected child is released.

## Controlled tests

Unit tests cover authentication, tampering, exact namespace isolation, expiry,
empty-policy rotation and retention of the last valid snapshot. Disposable VM
tests must then demonstrate a long-lived opt-in service that starts with no
deny, receives a real compiled Gate 3 deny while still running, loses external
egress on a subsequent call, recovers after authenticated expiry/rotation, and
does not affect a simultaneous control service.

Passing unit tests alone does not satisfy a promotion domain. Gate 4 remains a
controlled prototype until the VM evidence is frozen and evaluated under
report 106.
