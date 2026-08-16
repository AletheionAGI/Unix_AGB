# Unix-AGB — Aletheion Guard Bridge

**A proposed stateful security runtime for Linux that turns system behavior
into persistent causal state and compiles it into deterministic enforcement
policies.**

Unix-AGB is designed as an additional security layer over Ubuntu/Linux, not as
a new kernel or a replacement for AppArmor, Linux Security Modules, BPF, audit
logs, SIEM, or EDR. Its central separation of responsibilities is:

```text
Linux / Ubuntu             observation, identity, isolation, enforcement
AppArmor / LSM / BPF       stable base policy and security hooks
Aletheion Guard Bridge     state orchestration and policy control plane
ASM-CM                     bounded causal/associative state
Canonical Event Store      exact facts, authorization, and provenance
Optional LLM reader        human-readable explanation outside the hot path
```

## Status

This repository contains the Gate 0 architecture, versioned contracts, and an
audit-only functional skeleton plus two controlled Linux laboratory proofs.
The proofs observe real subprocesses and demonstrate a gateway decision causing
an external seccomp broker to return `EACCES`; neither is a production daemon
or a system-wide policy service.

Unix-AGB remains experimental research and is not a production security
system. Security efficacy, production performance, state compactness, and
detection claims have not been established.

Read the complete Portuguese specification:
[docs/Unix_AGB_Architecture_Specification_PTBR.md](docs/Unix_AGB_Architecture_Specification_PTBR.md).

## Design principles

- keep neural inference and LLMs out of the synchronous syscall hot path;
- treat the canonical event store, not neural state, as historical truth;
- isolate state by process, user, service, container, agent, tenant, or session;
- authorize before resolving evidence or sending it to a reader;
- allow AGB state to maintain or restrict base privileges, never expand them;
- preserve deterministic enforcement through cached, versioned policy;
- fail safely when state, checkpoints, event sequences, or runtimes are invalid;
- require measured improvement over deterministic and statistical baselines.

## Planned evolution

```text
Phase 0  Ubuntu observer, canonical events, audit-only evaluation
Phase 1  AGB runtime, ASM-CM integration, persistence and namespaces
Phase 2  explicit policy engine and dry-run decision cache
Phase 3  narrow AppArmor/BPF-LSM/cgroup enforcement pilot
Phase 4  security runtime for AI agents
Phase 5  Ubuntu-derived developer preview
Phase 6  optional minimal kernel work only if measurements justify it
```

See [ROADMAP.md](ROADMAP.md) for gates and deliverables.

## Repository map

```text
configs/       example runtime configuration
docs/          architecture decisions and operational contracts
fixtures/      deterministic synthetic event sequences
python/        fake ASM Unix-socket service for integration work
schemas/v1/    versioned JSON Schema contracts
scripts/       synthetic generator and plumbing benchmark
src/           Rust gateway, store, state, policy, enforcer, and CLI
tests/         Python contract and fake-ASM tests
```

Key documents: [contracts](docs/contracts.md),
[event model](docs/event-model.md), [namespaces](docs/namespaces.md),
[persistence](docs/persistence.md), [runtime stack ADR](docs/ADR-0001-runtime-stack.md),
[threat model](THREAT_MODEL.md), and [benchmark protocol](BENCHMARK.md).

## Gate 0 quickstart

Requirements: Rust stable and Python 3.11 or newer. No privileged Linux hooks
are used in this milestone.

```bash
make test
python3 scripts/generate_synthetic_events.py --count 3 \
  | cargo run --quiet --bin agb-gateway -- --store var/events.jsonl
cargo run --quiet --bin agbctl -- status
cargo run --quiet --bin agbctl -- events tail --limit 3
```

Run the fake ASM boundary as a separate Unix-domain JSONL service:

```bash
PYTHONPATH=python python3 -m agb_fake_asm.server \
  --socket var/run/fake-asm.sock
```

`make benchmark` measures only the deterministic fake-engine plumbing. It is
not evidence of security efficacy or production performance.

`make benchmark-gate2` runs the frozen 40-trajectory Gate 2 experiment across
event-local, sequence-rule, sliding-window, and deterministic stateful-proxy
modes. It also proves restart, corrupt-snapshot rejection, sequence-gap
abstention, and namespace isolation. Mode D is an integration seam for a future
ASM-CM backend; it is not learned state and cannot support an ASM efficacy
claim.

To run Mode D with the real promoted ASM-CM checkpoint, create the optional
environment with `python3 -m venv .venv && .venv/bin/pip install -r
requirements-asm.txt`, then provide the external checkpoint and source
fingerprints:

```bash
ASM_CM_CHECKPOINT=/path/to/checkpoint_final.pt \
ASM_CM_CHECKPOINT_SHA256=<sha256> \
ASM_SOURCE_ROOT=/path/to/ASM/src \
ASM_SOURCE_REVISION=<git-commit> \
make benchmark-gate2-asm-cm
```

The Make target uses CUDA by default. Set `ASM_DEVICE=cpu` explicitly on hosts
without a compatible GPU. The checkpoint is deliberately not copied into
Unix-AGB or committed.

`make benchmark-gate2-multiseed` runs the adversarial v2 corpus over exactly
three promoted checkpoints. It requires `ASM_CM_SEED{1,2,3}_CHECKPOINT` and
matching `ASM_CM_SEED{1,2,3}_SHA256` variables in addition to the ASM source
root and revision. The report separates ingest/query latency and records peak
CUDA allocated/reserved bytes.

## Reproducible causal proof

The first controlled proof uses two isolated processes that perform the same
terminal action: opening `/run/secrets/api-token`. Their prior histories differ:

```text
benign      exec → local configuration read → credential read  → shadow ALLOW
suspicious  exec → external network connect → credential read  → shadow DENY
```

Run `make causal-proof`. The executable verifies that the terminal operation
and resource are identical before accepting the divergent outcome, and prints
the causal evidence IDs used in each decision. The backend remains fake and
reports `applied: false`; this is a reproducible proof of trajectory-dependent
policy behavior, not real Linux enforcement or learned causal inference.

The live laboratory slice is available with `make live-proof`. It launches two
real Rust subprocesses, observes `execve`, `openat`, and `connect` through
`strace`, sends normalized events through the gateway, and installs a
process-local Landlock read denial only after the shadow decision. The report
is written to `var/live-proof/REPORT.json`. This is cooperative laboratory
evidence, not production telemetry or system-wide enforcement.

The first external-enforcement laboratory proof is `make seccomp-proof`. It
uses a separate broker process and seccomp user notification to deny `openat`
with `EACCES` for the restricted case. The broker now sends the real trajectory
to `agb-gateway`, which persists three events and returns the causal policy
decision before the kernel response. Reports and gateway JSONL stores are
written to `var/seccomp-proof/`. It is limited to one disposable file and does
not install a system-wide policy.

The enforcement edge also includes a versioned, expiring decision-cache
primitive in `python/agb_fake_asm/policy_cache.py`. Cache misses never invent
an allow decision; policy revision changes and TTL expiry invalidate entries.
`make seccomp-proof` now performs two identical protected opens and reports the
second request as a cache hit.

`make linux-capabilities` reports whether the host exposes the prerequisites for
the next observer step. The BPF laboratory observer is defined in
[`scripts/observe_live_bpf.bt`](scripts/observe_live_bpf.bt); it observes
`execve`, `openat`, and `connect` without blocking them. The external
enforcement boundary and its promotion criteria are documented in
[`docs/ADR-0002-external-enforcement.md`](docs/ADR-0002-external-enforcement.md).

## Scientific and security posture

The project must compare trajectory-aware state against strong baselines,
including static Linux/AppArmor policy, deterministic sequence rules,
sliding-window correlation, and conventional risk scoring. Automatic broad
enforcement is out of scope until false positives, recovery, resource bounds,
namespace isolation, rollback, and enforcement latency are demonstrated.

See [PRIOR_ART.MD](PRIOR_ART.MD) for lineage and non-claims.

## Naming and trademarks

“Unix-AGB” is a working project name. UNIX® is a registered trademark of The
Open Group. This project does not claim UNIX certification or endorsement.

## Authorship and licensing

Copyright © 2026 Felipe Maya Muniz.

Licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`). Commercial licensing is also available from AletheionAGI for
organizations that require proprietary integration, closed-source deployment,
or alternative licensing terms. Alternative terms apply only to Unix-AGB
components that AletheionAGI is legally entitled to license. Linux, Ubuntu,
AppArmor, BPF/eBPF, dependencies, and other third-party components remain under
their original licenses and must be handled separately.

See [LICENSE](LICENSE), [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md),
[NOTICE](NOTICE), [COPYRIGHT](COPYRIGHT), and [AUTHORS.md](AUTHORS.md).

Commercial licensing: `contact@aletheionagi.com`.
