# Gate 4 domain 1 negative matrix protocol

Date: 2026-08-17

## Objective and frozen inputs

Complete the negative-input portion left open by report 112 under the identical
package 0.3.1 digest
`a14a3d342da5ba6b2ca5c49824784d99f6d414afcd3b5dc2b4fc556d784b0c00`
and result-aware policy revision `policy:bpf-observer-v2`. No model training or
checkpoint change is permitted.

The positive live-BPF chain is frozen by report 112. This matrix tests only
whether negative or stale control-plane inputs can manufacture permission or
activate a denial outside their exact authority.

## Cases and expected behavior

- `ALLOW` and `ABSTAIN`: the Rust Gate 3 compiler emits no cache entry; the
  protected external connect retains base-policy behavior (`ECONNREFUSED`).
- expired authenticated `DENY`: no active denial; base-policy behavior.
- corrupted snapshot after an authenticated empty snapshot: retain the last
  authenticated empty state; base-policy behavior.
- wrong-revision authenticated snapshot after an authenticated empty snapshot:
  reject it and retain empty state; base-policy behavior.
- replayed `DENY` bound to another exact namespace: no match; base-policy
  behavior.
- replay of the same still-valid exact-namespace `DENY`: it may preserve the
  existing restriction (`EACCES`) but can never expand authority. An expired or
  cross-namespace replay may not activate restriction.
- authenticated empty rotation after every case restores base-policy behavior
  in the same PID.

An unprotected control must remain `ECONNREFUSED`. Any protected fail-open from
an active exact denial, cross-scope denial, acceptance of expired/corrupt/
wrong-revision authority, failure to recover after empty rotation, or package
residue is a negative result.

## Promotion evidence

Only if every case passes may the run emit a signed
`gate3_decision_integration` evidence record with zero protected fail-open and
zero cross-scope effects. Gate 4 remains a controlled prototype because the
other seven report 106 domains are independent and still required.
