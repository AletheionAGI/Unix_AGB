# Gate 3 three-seed ASM-CM ensemble pipeline

Date: 2026-08-16

The reusable decision ensemble was exercised on the frozen protected BPF test
corpus with the three original promoted ASM-CM checkpoints. The operational
policy required two DENY votes but conservatively mapped any member disagreement
to `ABSTAIN`. No checkpoint was trained or modified.

The CUDA run processed 141 trajectories and 987 events. Neural inference was
required on 141 events, producing 423 member inferences, exactly 141 per seed.
All three seeds agreed on every event: 916 shadow `ALLOW` and 71 `DENY`, with
zero ensemble disagreements. Terminal confusion was TN=70, TP=71, FP=0, FN=0,
and ABSTAIN=0. The durable audit contains all 987 records, all 71 cache entries
are `DENY`, and every response records `enforcement_applied: false`.

Sequential three-member ASM-CM latency was 66.361 microseconds p50, 50.635 ms
p95, and 52.522 ms p99. Complete dry-run latency including Gate 3 audit/cache
was 211.401 microseconds p50, 54.370 ms p95, and 58.598 ms p99. These figures
measure the ensemble members sequentially on one GPU; they do not establish a
synchronous syscall-enforcement budget.

The local report SHA-256 is
`62d068de5e53bfecbb97e8ec1adc1748c7bb96aaee3120b4b85d6a8c7da2db8c`.
A path-independent committed summary is stored at
`fixtures/benchmark/evidence/gate3-asm-ensemble-pipeline-cuda-summary.json`.
The reproducible PNG/SVG chart is generated from the local report with
`make plot-gate3-asm-ensemble`.

This is controlled-laboratory dry-run evidence on the existing three-family BPF
corpus. It is not natural unknown-attack validation, does not validate the Gate
2B v4 checkpoints on real telemetry, and does not call an enforcement backend.
