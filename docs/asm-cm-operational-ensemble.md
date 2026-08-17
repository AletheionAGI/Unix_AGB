# Operational ASM-CM canonicalization and ensemble seam

This engineering seam does not change the frozen Gate 2B findings. Gate 2B v1
and v4 remain negative under their declared criteria; v5 remains a successful
2-of-3 confirmation on a fresh split from the same synthetic generator family.

## Reusable components

`agb_fake_asm.canonicalization` provides a label-independent, trajectory-local
first-occurrence encoder. Its equivalence test compares it with the frozen v4
implementation. The frozen implementation itself is intentionally unchanged,
because its source hash is embedded in the v4 checkpoints.

`agb_fake_asm.ensemble` accepts independent stateful decision engines, validates
that their revisions remain aligned, unions causal evidence, exposes every vote,
and accumulates disagreement count and rate. It supports two explicit policies:

- `abstain` (operational default): any member disagreement returns `ABSTAIN`, so
  no model-derived `DENY` is compiled into the deny-only enforcement cache;
- `majority`: a 2-of-3 vote is authoritative, matching the declared v5 rule.

The majority result is retained as telemetry even when the operational result
is `ABSTAIN`. This makes later operator review possible without silently turning
a split neural vote into enforcement.

## Gate 3 dry-run integration

The existing single-checkpoint command remains unchanged. The repository-local
protected BPF corpus and the three original promoted checkpoints are the default
three-member dry-run inputs:

```sh
make benchmark-gate3-asm-ensemble-pipeline
```

The report adds checkpoint fingerprints, complete-pipeline latency, and ensemble
telemetry. The command performs inference only; it does not train or modify a
checkpoint. `AGB_ENSEMBLE_DISAGREEMENT_ACTION=majority` is an explicit opt-in.
The default cache HMAC key is deliberately marked for local dry-run use only;
override `AGB_GATE3_CACHE_KEY` for any retained or shared laboratory result.

The frozen v4 checkpoints must not be treated as natural-telemetry checkpoints
merely because this seam can load three models. Their evidence belongs to the
neutral synthetic protocol. A later controlled validation must establish that
the selected three checkpoints share the target event vocabulary, policy
semantics, and acceptable resource cost before any enforcement pilot.
