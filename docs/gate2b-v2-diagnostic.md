# Gate 2B v2 diagnostic protocol

Gate 2B v1 remains an immutable negative result: the three ASM-CM seeds did
not support the preregistered causal-generalization hypothesis. This v2
protocol diagnoses that failure; it does not replace the v1 corpus, thresholds,
checkpoints or final report and cannot retroactively promote Gate 2B.

## Phase 1: minimum-capacity checks

Three independent runs reload the same initial checkpoint and receive balanced
sets of 2, 8 and 32 calibration trajectories. Distractors are removed, while
the neutral terminal query and the benign/malicious equality distinction are
preserved. Each run must reach at least 99% training accuracy. Failure stops
the causal ladder and points to optimization, the adapter, objective or
representation rather than long-range memory.

The diagnostic classifier uses only logits 2 and 3 and balanced mini-batches
(one example per class by default, configurable for a larger batch).
Every reporting window records mean, median, p95 and maximum cross-entropy;
pre-clipping gradient norm; training confusion and confidence; parameter norm;
and its relative change from initialization. The latter is a low-overhead proxy
for parameter movement, not an exact per-step update norm.

## Phase 2: controlled causal ladder

The ladder runs only if all minimum-capacity checks pass. A fresh checkpoint is
trained at distances 4, 16, 64, 256 and 1024 in order. At every stage it records
training fit, validation at the current distance, and zero-shot validation at
the next distance. Failure to fit a stage stops the ladder. This distinguishes:

1. memorizing a small balanced set;
2. generalizing the equality relation to unseen trajectories;
3. retaining that relation through increasingly many distractors.

No sealed test corpus is accepted or evaluated. Composition and hidden-family
testing require a later, separately declared experiment after the failure mode
is understood.

## Phase 3: relational probes

Once the ladder result exists, a resumable command runs counterfactual pairs
with fixed agent/tool/family and new sessions/destinations. It evaluates raw
identifiers, a global bijective permutation of every entity token, full-model
fine-tuning, and a freshly initialized vocabulary head over a frozen encoder.
An additional engineered representation inserts a derived equality token. It
is an upper bound demonstrating whether the classifier can consume an explicit
relation; it is not evidence that ASM-CM discovered the relation.

## Operator command

The run uses one initial promoted checkpoint and normally ends in minutes when
a minimum-capacity check fails. A successful full ladder can take longer.

```sh
cd ~/dev/ai/Unix_AGB

ASM_CM_CHECKPOINT=../gitlab/ASM/runs/asm_c2_fw_lm_confirmation/seed_1/candidate/checkpoint_final.pt \
ASM_CM_CHECKPOINT_SHA256=96293688518fc0a2e83525af6ad28d16f39677980432762328bf4ad8aac654de \
ASM_SOURCE_ROOT=../gitlab/ASM/src \
ASM_DEVICE=cuda \
make diagnose-gate2b-v2
```

Outputs are written to `var/benchmark/gate2b-v2-diagnostic.json` and
`var/benchmark/gate2b-v2-diagnostic.png`. The JSON explicitly records
`test_evaluated: false`.

After the first command completes, reuse its capacity/ladder result and run only
the relational probes:

```sh
ASM_CM_CHECKPOINT=../gitlab/ASM/runs/asm_c2_fw_lm_confirmation/seed_1/candidate/checkpoint_final.pt \
ASM_CM_CHECKPOINT_SHA256=96293688518fc0a2e83525af6ad28d16f39677980432762328bf4ad8aac654de \
ASM_SOURCE_ROOT=../gitlab/ASM/src \
ASM_DEVICE=cuda \
make diagnose-gate2b-v2-relational
```

This produces `gate2b-v2-relational.json` and a three-panel PNG containing
minimum-capacity learning, memorization, and train/validation/zero-shot causal
distance curves.
