# Gate 4 live Gate 3 ensemble protocol

Date: 2026-08-17

## Frozen objective and limitation

This experiment replaces report 108's handcrafted denial with the real Gate 3
ensemble and Rust policy compiler while an opt-in service remains alive under
seccomp supervision. It uses the three frozen confirmation checkpoints and ASM
source revision `4c8eddf2f07d9aec800769323d7e1effbd64815a` without training.

The input is explicitly a frozen malicious controlled trajectory rebound by an
`agent-broker` adapter to the live service's exact boot-ID/PID/start-time
namespace. It is not newly captured BPF telemetry and cannot satisfy the full
promotion domain by itself. The purpose is to validate the model -> state ->
policy -> authenticated cache -> live guardian -> kernel denial chain.

## Frozen behavior

- Package 0.3.1 accepts any unexpired authenticated Gate 3 `DENY` for the exact
  namespace as a trajectory-level trigger for future external-egress
  containment. The originating operation remains visible in the audit.
- The ensemble uses 2-of-3 voting with disagreement action `abstain`.
- The Rust policy engine must durably audit the decision and write a DENY-only
  HMAC-authenticated cache under revision `policy:bpf-observer-v1`.
- Before cache publication the protected service must not receive `EACCES`.
  After publication, a later external connect must receive `EACCES` while an
  unprotected control remains unaffected.
- An authenticated empty rotation must restore the baseline behavior.
- Any ensemble `ALLOW`/`ABSTAIN`, missing cache entry, revision mismatch,
  authentication failure, protected fail-open, or cross-scope effect is a
  negative result.

The run is supported only for this controlled end-to-end binding if every item
passes. Gate 4 remains a controlled prototype, and full promotion still
requires live independent telemetry plus the remaining report 106 domains.
