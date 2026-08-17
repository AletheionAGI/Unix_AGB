# Gate 3 natural and novel-controlled ensemble validation

Date: 2026-08-16

The validation bundle was frozen before evaluation with SHA-256
`b913d7c3877f5bfe83231c5c752f9d8a8f453bb7233b3d9350920ef7a326a609`.
It bound a newly reviewed system-wide natural corpus, a new BPF-controlled
delayed-composition corpus, the three promoted checkpoints, the ASM source
revision, the conservative disagreement policy, and all pass/fail criteria.

The natural corpus contains 833 human-reviewed benign trajectories and 64,355
events. Its test split contains 697 trajectories and 60,521 events: 570 reviews
with high confidence and 127 with low confidence. The selective adapter returned
TN=697, FP=0, ABSTAIN=0, and zero member disagreement. Crucially, it performed
zero neural inferences because this external telemetry contained no configured
protected-query labels. This is evidence for selective pipeline behavior and
zero observed pipeline false positives, not a measurement of neural FPR on
natural sensitive queries.

The controlled test contains 140 BPF-observed trajectories across three new
`*-delayed` composition names. It produced TN=69, TP=71, FP=0, FN=0,
ABSTAIN=0, 100% recall and precision, and zero member disagreement. All three
members performed 140 inferences, for 420 total. Query latency was 72.891 ms p50,
82.276 ms p95, and 99.959 ms p99 with the members executed sequentially.

All preregistered criteria passed and the final JSON records `supported: true`.
This does not establish natural malicious recall, unknown-attack detection, or
production enforcement suitability. The new controlled trajectories preserve
the same three semantic relation classes and vary composition/distance; they are
not natural unknown attacks. Every response remained dry-run and no enforcement
backend was called.

The local final report SHA-256 is
`7c1dfe28df0d139a624c21d58e833b6e517aa0ea25f7484d93043222ff2a7ba8`.
The path-independent summary is committed at
`fixtures/benchmark/evidence/gate3-natural-controlled-validation-summary.json`.
The PNG/SVG chart is reproducible with `make plot-gate3-validation` and keeps
the natural zero-inference limitation visible in the figure itself.
