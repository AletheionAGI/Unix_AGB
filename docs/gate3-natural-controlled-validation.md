# Gate 3 natural and novel-controlled ensemble validation

## Status and separation from prior evidence

This protocol is preregistered before its test corpora are evaluated. It does
not revise Gate 2B v1, v4, or v5, and it does not reinterpret the protected BPF
corpus used by reports 78, 81, and 88. Previously observed corpus hashes and the
three prior protected-family names are rejected by the freezer.

The question is narrower than unknown-attack validation: can the frozen
three-checkpoint ensemble retain low false positives on newly reviewed natural
benign activity and retain controlled recall on newly captured delayed causal
compositions? Passing does not establish efficacy on natural malicious attacks.

## Frozen inputs

The decisive bundle contains physically separate corpora:

1. natural external telemetry collected by BPF, independently reviewed, with at
   least 30 benign test trajectories for false-positive monitoring;
2. protected controlled telemetry collected by BPF, with at least 20 benign and
   20 malicious test trajectories across at least three new family names.

Synthetic provenance is rejected. Exact corpus and checkpoint SHA-256 values,
the 2-of-3 vote, `ABSTAIN` disagreement behavior, criteria, and
`test_evaluated: false` are written before model evaluation. A freeze cannot be
overwritten.

The controlled profile uses real processes and inert files/loopback under
`var/telemetry/`. Its new `*-delayed` compositions insert four benign file-open
distractors between the causal trigger and terminal action. These are unseen
compositions, not new semantic attack classes.

## Preregistered criteria

All criteria must pass:

- natural benign false-positive rate no greater than 1%;
- controlled false-positive rate no greater than 1%;
- controlled malicious recall at least 95%;
- decision coverage exactly 100% in both strata;
- member disagreement rate no greater than 5% in both strata;
- every member remains visible in telemetry;
- enforcement remains disabled.

`ABSTAIN` is not counted as a true negative. Any failed criterion is reported as
a negative result; thresholds are not changed after evaluation.

## Operator workflow

Capture natural activity while intentionally using a declared set of ordinary
applications. Collection is privileged and may record executable names, paths,
and network metadata, so the operator must choose the observation window and
review the local queue before export.

```sh
make capture-gate3-natural-validation
make prepare-gate3-natural-review
make review-gate3-natural-validation
make export-gate3-natural-validation
```

Capture the new controlled compositions:

```sh
make gate3-novel-controlled-lab
```

Freeze before opening either test set to the ensemble:

```sh
make freeze-gate3-validation
```

Only after inspecting and retaining the freeze, run the GPU evaluation:

```sh
make evaluate-gate3-validation
```

The evaluator refuses changed corpora, changed checkpoints, an already-used
output, or a freeze that does not record `test_evaluated: false`. It performs no
training and calls no enforcement backend.
