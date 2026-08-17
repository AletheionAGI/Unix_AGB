# Gate 4 coordinated formal campaign preregistration

Date: 2026-08-17

## Scope

This preregistration coordinates five still-independent Gate 4 domains:
`real_application_coverage`, `concurrency_endurance`,
`namespace_application_isolation`, `production_resource_latency`, and
`ubuntu_boot_matrix`. It does not alter the already-supported Gate 3 decision
integration domain and cannot promote Gate 4 by campaign completion alone.

The frozen inputs are package 0.3.1 with SHA-256
`a14a3d342da5ba6b2ca5c49824784d99f6d414afcd3b5dc2b4fc556d784b0c00`
and policy revision `policy:bpf-observer-v2`. Eligible runs last at least 28,800
monotonic seconds and contain 32 simultaneous groups across three application
classes. The identical profile is evaluated on Ubuntu 24.04 and 26.04.

## Host-bound freeze

Before freezing, `make gate4-formal-vm-prepare` explicitly installs and enables
the opt-in package inside the disposable VM and changes its Gate 3 cache
revision to `policy:bpf-observer-v2`. The preparer requires root, explicit
`--apply`, a detected VM, an eligible Ubuntu release and the exact package
digest; it refuses activation on a physical host. This is an intentional
VM-local state change and must not be run on the developer workstation.

`scripts/build_gate4_formal_manifest.py` must run inside each disposable VM. It
refuses a non-Ubuntu or unregistered release, a changed package, missing real
application executables, or an inactive long-lived
`unix-agb-egress-guardian.service`. It then writes a host-bound manifest and
prints its digest. `--allow-non-ubuntu` exists only for orchestration
qualification and makes the result ineligible for promotion.

The declared application classes are a loopback Python HTTP server, a D-Bus
session daemon and a systemd-inhibited long-running process. Their presence is
not by itself evidence that enforcement worked. Protected external, protected
loopback and unprotected external controls must be recorded separately, and
the real systemd guardian must remain active throughout the run.

## Preregistered budgets

The initial conservative per-process ceilings are 1,440,000 CPU ticks, 128 MiB
RSS and 128 file descriptors. Total campaign audit growth is limited to 256
MiB. Successful probe latency must remain at or below 50 ms p50, 150 ms p95 and
500 ms p99. These are frozen engineering thresholds, not claims that the
current implementation has met them. A complete sample set is mandatory.

## GUI and unattended execution

The formal runner supports both headless and `--gui` execution. The GUI binds
only to `127.0.0.1`, reads the same atomic status file and has no authority over
workloads or evidence. Closing the browser does not stop the campaign. Closing
the runner does, and produces an interrupted result that is ineligible.

For a campaign running inside Multipass, the repository/output directory should
be mounted from the host. `make gate4-formal-gui-view` then runs on the host and
reads that shared output while remaining bound to host `127.0.0.1`; no VM
network listener or port exposure is required. The VM runs `make gate4-formal`
headless. This viewer is independent of campaign lifetime and stops with
Ctrl-C without interrupting the VM runner.

## Independent evaluation

`scripts/evaluate_gate4_formal_campaign.py` verifies the manifest and heartbeat
chain, recomputes probe percentiles, checks declared resource ceilings and
emits a separate result for every targeted domain. Auxiliary VM, namespace,
control and audit-growth records must be bound to the exact profile, manifest,
artifact and policy digests and must report zero fail-open and cross-scope
effects. A missing or mismatched record remains `supported: false`.
`complete: true` and the runner's `promotion_eligible` field are necessary but
not sufficient. This prevents orchestration success from becoming a scientific
verdict. Domain results must still be HMAC-authenticated and consumed by the
existing Gate 4 promotion evaluator; this campaign evaluator does not replace
that final authorization boundary.

The eight-hour execution and privileged namespace/reboot matrices must be run
by the operator in disposable VMs. No elapsed time, reboot, namespace boundary
or positive control may be simulated or inferred.
