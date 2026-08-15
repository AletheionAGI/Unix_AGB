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

This repository currently contains the initial architectural specification.
Unix-AGB is experimental research and is not yet a production security system.
Security, performance, state compactness, isolation, and detection claims must
be established by implementation and reproducible benchmarks.

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
docs/          architecture and supporting specifications
```

The implementation layout proposed by the architecture will be introduced
incrementally as roadmap gates begin.

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
