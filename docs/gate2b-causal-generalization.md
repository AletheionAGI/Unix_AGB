# Gate 2B causal generalization challenge

## Preregistered hypothesis

Under the same neutral event stream and a declared state budget, ASM-CM will
degrade more slowly than deterministic FSM, CEP graph, sliding-window,
conventional risk-score, and GRU baselines as causal distance, distractors and
held-out composition increase. The model receives no `credential`, `admin`,
`persistence`, sensitivity, trust, or class label token.

This is falsifiable. Gate 2B fails to support the hypothesis unless all three
predeclared seeds satisfy all of the following on the untouched test splits:

1. ASM-CM accuracy at distances 256 and 1024 exceeds the best frozen baseline
   by at least 5 percentage points;
2. hidden-family accuracy exceeds the best frozen baseline by at least 5
   percentage points;
3. false-positive rate is no more than 1 percentage point worse than the best
   baseline;
4. the advantage appears in every seed, not only in the mean;
5. checkpoint, dataset, baseline report and source fingerprints are complete.

Failure, a tie, or a resource cost judged disproportionate is a valid negative
result and blocks any claim that ASM-CM is scientifically necessary for
Unix-AGB. Gate 2 controlled-lab promotion remains an engineering result and is
not retroactively interpreted as this evidence.

## Neutral protocol and leakage controls

Each JSONL record contains abstract agent, session, tool, family and event graph
IDs; events contain only `subject`, `relation` (`R0`–`R5` or noise `RN`) and
`object`. The terminal relation is identical across classes. The label is
outside `tokens` and is used only as a supervised target.

Calibration, validation, held-out composition and hidden-family splits are
generated independently. A structural signature containing agent, tool,
family and non-noise relation grammar may occur in only one split. Family `F2`
is absent from calibration. Baselines fit only calibration, select only on
validation, and are serialized in a report before ASM-CM training is allowed.
Calibration/validation and test are written to physically separate JSONL files.
The public manifest commits to both hashes, while neither the baseline freezer
nor the ASM trainer accepts a test-corpus argument.

The initial generator is a protocol implementation, not final scientific data.
It must be reviewed and frozen before the decisive run; generator changes after
observing test results require a new protocol version.

## Reproducible preparation

```sh
make gate2b-neutral-corpus
make benchmark-gate2b-baselines
```

Training is intentionally a separate operator action because it uses the GPU.
The trainer verifies the dataset and frozen baseline fingerprints, reads only
calibration labels, uses validation during the curriculum, and records
`test_evaluated: false` in the checkpoint metadata and training report.

After reviewing and committing the protocol, the complete three-seed run is:

```sh
./scripts/run_gate2b_multiseed_training.sh
```

It runs the steps in the only permitted order and opens the sealed test splits
only after all three candidate checkpoint hashes exist. Defaults point to the
three locally promoted ASM-CM checkpoints and CUDA; every path and curriculum
can be overridden through the environment. Outputs remain under
`var/benchmark/` and are not evidence until reviewed and summarized without
machine-specific paths.

The final evaluator automatically renders
`var/benchmark/gate2b-comparison.png` and `.svg`. Each test split gets a causal
distance curve for every frozen baseline, the three-seed ASM-CM mean, and a
shaded minimum–maximum seed band. Rendering uses Matplotlib's headless `Agg`
backend, so no desktop session is required.
