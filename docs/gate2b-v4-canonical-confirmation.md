# Gate 2B v4 canonical confirmation

V1 failed with raw global IDs. V2 localized the failure to relational
generalization, and v3 showed on a short diagnostic that trajectory-local IDs
recover permutation-invariant binding. V4 is a fresh confirmatory synthetic
run declared before its new sealed split is evaluated.

The generator family, state budgets, FSM, CEP, sliding-window, risk-score, GRU,
causal distances, composition holdout, hidden family, and original five-point
criteria remain unchanged. V4 uses a new dataset seed and physically separate
public/test files because the v1 test has already been observed. Both raw and
canonical ASM-CM receive identical public trajectories, balanced two-example
batches, two-logit loss, curriculum, learning rate, steps and three initial
promoted checkpoints.

Canonicalization is online and label-independent: entity tokens are mapped to
trajectory-local slots in order of first occurrence, while control/relation
tokens remain unchanged. Repeated entities reuse their slot. Its implementation
hash is embedded in every canonical checkpoint and its evaluation latency is
reported separately.

The hypothesis is supported only if every canonical seed satisfies the original
criteria on the fresh test: at least five percentage points over the best frozen
baseline at distances 256 and 1024 and on the hidden family, with false-positive
rate no more than one point worse. Raw ASM-CM is a paired representation control.
The result remains limited to the synthetic generator family.

The complete operator-side run is:

```sh
./scripts/run_gate2b_v4_multiseed.sh
```

It creates a fresh corpus, freezes baselines, trains six candidates (raw and
canonical for three seeds), verifies all fingerprints, opens the new sealed test
only after all six checkpoints exist, measures canonicalization, and renders a
raw/canonical comparison PNG and SVG.

After a final report exists, the runner refuses to overwrite it. Setting
`AGB_GATE2B_V4_ALLOW_REPLAY=1` permits an explicit deterministic reproduction,
which is not interpreted as another fresh confirmation.
