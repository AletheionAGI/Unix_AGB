# Gate 4 live Gate 3 ensemble

Date: 2026-08-17

## Frozen artifact and input

Report 109 was executed with package
`unix-agb-egress-guardian-lab_0.3.1_all.deb`, SHA-256
`a14a3d342da5ba6b2ca5c49824784d99f6d414afcd3b5dc2b4fc556d784b0c00`,
on the disposable Ubuntu 24.04.4 enforcement VM. The model ran on the local
RTX 4090 with the three frozen confirmation checkpoints and ASM source revision
`4c8eddf2f07d9aec800769323d7e1effbd64815a`. No training occurred.

The input limitation is material: one frozen malicious
`protected-credential-egress-delayed` trajectory was explicitly rebound by an
`agent-broker` adapter to the already-running protected service's exact
boot-ID/PID/start-time namespace. The corpus declares this controlled replay in
its label source and provenance. It is not new BPF telemetry from that service
and its manifest correctly records `promotion_eligible: false`.

## End-to-end result

The service began under an authenticated empty cache and completed 572 private
gateway attempts without `EACCES`. The real ensemble then processed 11 events.
Each of the three members performed exactly one inference; 2-of-3 voting
produced 10 `ALLOW` and one `DENY` with zero disagreement. The Rust Gate 3
policy wrote 11 durable audit records and one DENY-only authenticated cache
entry under `policy:bpf-observer-v1`.

The compiled decision originated at `file.open`, state revision 11, with
decision ID
`dec:1e0cf86bbd384ba4b96424cede3ba1ac330bc2256b64b7a7bc7d4a473851f236`.
Package 0.3.1 intentionally treats any active Gate 3 trajectory denial for the
exact namespace as a trigger for future external-egress containment. After the
cache was published atomically, the next protected connect returned `EACCES`.
The guardian audit recorded the same decision ID and reason
`ACTIVE_GATE3_TRAJECTORY_DENY:file.open`.

An unprotected control continued to the private gateway and returned
`ECONNREFUSED`. An authenticated empty rotation restored `ECONNREFUSED` for the
protected service. Package purge then left no unit, account, process, listener,
cgroup, configuration, state or installed path.

The guardian recorded 576 calls: 575 allows and one deny. Its small-sample
latency was 248 microseconds p50, 327 microseconds p95, 387 microseconds p99 and
418 microseconds maximum. The Gate 3 cache, audit, input and report hashes are
preserved in the committed summary artifact.

## Verdict

`controlled_chain_supported: true`: the frozen ensemble, real Gate 3 policy
compiler, authenticated cache, live guardian and kernel denial were connected
successfully without a protected fail-open or cross-scope effect.

`first_promotion_domain_supported: false`: the causal trajectory was a
controlled rebound replay rather than independent live BPF telemetry. Gate 4
remains `controlled-prototype`. The next experiment must capture a newly
executed controlled trajectory from the already-supervised service and feed
those unmodified events to the same frozen chain. Gate 2B v1/v4 negative
results and Gate 2B v5 confirmation are unchanged.
