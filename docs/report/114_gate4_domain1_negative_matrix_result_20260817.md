# Gate 4 domain 1 negative matrix result

Date: 2026-08-17

## Frozen execution

Report 113 was executed on the disposable Ubuntu 24.04.4 VM with the identical
package 0.3.1 artifact used by report 112, SHA-256
`a14a3d342da5ba6b2ca5c49824784d99f6d414afcd3b5dc2b4fc556d784b0c00`,
and policy revision `policy:bpf-observer-v2`. No training or model change
occurred.

The Rust Gate 3 compiler was separately exercised with `normal` and `unknown`
state. It returned `ALLOW` and `ABSTAIN`, respectively, and created no cache
file. Thus these effects were tested as compiler projections, not merely
represented by a handcrafted empty snapshot.

## Live negative matrix

Seven live cases passed against the persistent guardian:

- `ALLOW` projection: base behavior, then successful empty rotation;
- `ABSTAIN` projection: base behavior, then successful empty rotation;
- expired authenticated denial: ignored;
- corrupt snapshot after authenticated empty state: rejected while empty state
  remained authoritative;
- authenticated wrong-revision snapshot: rejected;
- valid denial replayed into another exact namespace: no match;
- replay of a still-valid exact-namespace denial: remained restrictive with
  `EACCES`, never manufactured permission.

Every non-authoritative case returned the private gateway's base
`ECONNREFUSED` result. The active exact denial returned `EACCES`. Authenticated
empty rotation restored `ECONNREFUSED` in the same PID after every case. The
unprotected control also returned `ECONNREFUSED`. There were zero protected
fail-open observations and zero cross-scope effects. Package purge again left
no AGB unit, account, process, listener, cgroup, configuration, state, or
installed path.

## Authenticated evidence and verdict

The successful record was signed under protocol
`unix-agb-gate4-promotion-v1`, bound to the exact package digest and v2 policy
revision, and verified before the ephemeral signing key was destroyed. Its
HMAC is `c5a83a7d...c00f0`; the key fingerprint and artifact hashes are preserved
in the committed summary.

`gate3_decision_integration: supported`. The first of eight Gate 4 promotion
domains is now formally complete for the frozen artifact/revision evidence set.

`gate4_status: controlled-prototype`. The evaluator correctly reports the
other seven domains as `EVIDENCE_MISSING`; this result does not promote Gate 4
as a whole and does not alter Gate 2B v1/v4 negatives, v5's synthetic-family
confirmation, or the limitation concerning natural unknown attacks.
