# Gate 2B v3 identity-binding diagnostic

Gate 2B v2 showed that ASM-CM can memorize raw-ID trajectories but does not
generalize their equality relation. V3 compares identity representations
without opening the sealed Gate 2B test and without reinterpreting v1 or v2.

Five full-model arms use the same fixed-composition, disjoint-destination
counterfactual probe and exactly 400 optimization steps:

1. raw entity IDs;
2. trajectory-local IDs assigned by first occurrence;
3. raw IDs with one fresh global permutation per training batch;
4. local canonical IDs plus an auxiliary cosine matching objective between the
   setup-destination and terminal-destination states;
5. a derived equality token as an explicitly labeled engineered upper bound.

Every mini-batch contains the benign and malicious members of the same
counterfactual pair. Validation uses new sessions and a destination-token range
disjoint from training. A second evaluation globally permutes all validation
entity IDs. Canonicalization is applied after this permutation, so invariance is
testable without exposing a label.

The auxiliary objective receives `+1` for equal references and `-1` for
different references through cosine embedding loss. It is supervised relational
inductive bias and must be reported separately from raw ASM-CM performance.
Unlike the explicit-equality upper bound, it does not insert the answer into the
input stream.

Run on one promoted initial checkpoint:

```sh
ASM_CM_CHECKPOINT=../gitlab/ASM/runs/asm_c2_fw_lm_confirmation/seed_1/candidate/checkpoint_final.pt \
ASM_CM_CHECKPOINT_SHA256=96293688518fc0a2e83525af6ad28d16f39677980432762328bf4ad8aac654de \
ASM_SOURCE_ROOT=../gitlab/ASM/src \
ASM_DEVICE=cuda \
make diagnose-gate2b-v3-binding
```

Outputs are `var/benchmark/gate2b-v3-binding.json` and `.png`. The report
fingerprints the probe and records `test_evaluated: false`.
