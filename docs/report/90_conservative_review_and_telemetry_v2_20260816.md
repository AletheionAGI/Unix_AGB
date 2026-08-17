# Conservative review and telemetry v2

This engineering increment does not change the Gate 2B v1/v4 negative results
or the Gate 2B v5 confirmatory result. It also does not promote enforcement.

The independent reviewer now supports `inconclusive`. Such a decision completes
the review queue but is excluded from the binary evaluation corpus. A separate
conservative auditor never converts natural telemetry into a malicious label;
it excludes low-confidence reviews, requested-only syscalls, unresolved network
destinations, missing process identity, and truncated windows.

The auditor was run against the 833 previously reviewed Gate 3 natural
trajectories. It retained zero binary labels and marked all 833 inconclusive,
because the historical v1 collector recorded syscall entry only. This does not
invalidate report 89's selective-pipeline observation, but it reinforces its
stated limitation: that corpus is not neural false-positive evidence.

The v2 BPF path pairs syscall entry and exit before emitting file-open, bind,
or connect evidence. It records the kernel return value and distinguishes
`allowed`, permission `denied`, and other `failed` outcomes. Successful exec is
observed at `sched_process_exec`. Socket creation, bind, and connect are distinct
operations. Subject identity now includes PPID and command line.

An optional three-worker ensemble scheduler was added behind
`AGB_ENSEMBLE_PARALLEL_MEMBERS=1`. It preserves member order, voting, abstention,
and disagreement telemetry. It is an optimization candidate, not a promoted
default; sequential and parallel CUDA latency must be compared on the same
frozen corpus.

Validation completed locally with 75 Python tests and 12 Rust tests. BPF source
compilation could not be validated in the non-interactive session because
tracingfs and sudo require operator privileges. No fresh capture and no GPU
evaluation are claimed by this report.

Operator validation command:

```sh
sudo bpftrace --mode codegen scripts/observe_live_bpf.bt 4294967295 0
```

After a fresh protected benign capture, freeze it before either ensemble run.
Run the sequential benchmark first, retain its report, then use a different
audit/cache/output path for the parallel candidate. Keep disagreement action at
`abstain`; do not enable enforcement based on this optimization benchmark.
