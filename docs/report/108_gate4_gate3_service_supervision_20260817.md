# Gate 4 Gate 3 service supervision

Date: 2026-08-17

## Artifact and scope

The report 107 controlled protocol was implemented as package
`unix-agb-egress-guardian-lab_0.3.0_all.deb`, SHA-256
`ecf51aaf34c573b3156c9f478401ea859ff56c3732408718e0794cae6fb8a39d`,
and tested in the disposable Ubuntu 24.04.4 VM. No GPU training or new neural
inference was performed. The policy transition used a controlled writer that
emits the same authenticated Gate 3 cache format; consequently this run
validates the runtime binding mechanism but does not yet satisfy report 106's
real Gate 3 decision-integration domain.

Package 0.3.0 installs seccomp user notification before the protected service
executes. Launcher and guardian independently derive the BPF process namespace
from boot ID, PID and start time. The guardian loads only an exact-revision,
HMAC-authenticated Gate 3 cache and consults it on every external connect. A
matching unexpired namespace-level `network.connect` denial applies external
egress containment. This is not destination-specific enforcement.

## Controlled result

A long-lived transient systemd service first ran under an authenticated empty
cache. Five baseline calls reached the private Multipass gateway and returned
`ECONNREFUSED`, showing that seccomp continued them. An authenticated denial
for the exact namespace was then installed; `EACCES` first appeared at attempt
7. While that denial was active, an unprotected control still returned
`ECONNREFUSED`.

The cache was replaced by malformed JSON. The next five protected attempts all
remained `EACCES`, demonstrating retention of the last authenticated snapshot.
An authenticated empty rotation then restored `ECONNREFUSED` on the following
protected attempt.

The final audit contained 16 records: 9 allows and 7 denies, including 7
`ACTIVE_GATE3_TRAJECTORY_DENY`, 7 `NO_ACTIVE_GATE3_DENY`, and 2 loopback
records. Audit latency was 191 microseconds p50 and 276 microseconds p95/p99
and maximum. This is a small functional sample, not a production capacity
measurement.

After the experiment, package purge left no unit, account, process, listener,
cgroup or installed/state/configuration path according to the cleanup auditor.

## Preserved negative and inconclusive attempts

The first short workload ended without observing `EACCES`, and its separate
control command contained a quoting error. A later tamper attempt began after
its workload had already ended and was inconclusive. Neither is counted as a
pass.

A clean restart then exposed a real readiness bug: systemd `Type=simple`
reported the guardian active before `control.sock` existed, so the launcher
failed without releasing the protected child. The launcher now waits at most
two seconds for the socket and fails closed on timeout. The complete matrix was
rerun with the corrected final artifact and passed.

## Verdict

The evidence records `supported: true` only for the controlled service-policy
transition mechanism. `first_promotion_domain_supported` remains false because
the decision was injected by the controlled cache writer rather than produced
end-to-end by the real Gate 3 ensemble/policy compiler during the live service
trajectory. Gate 4 therefore remains `controlled-prototype`. Gate 2B v1/v4
negative results and the Gate 2B v5 confirmation are unchanged.
