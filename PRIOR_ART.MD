# Prior Art and Project Lineage

Unix-AGB — Aletheion Guard Bridge is a proposed stateful security runtime for
Linux. It combines existing operating-system security mechanisms with compact
causal state, canonical evidence, explicit policy, and deterministic
enforcement.

## Related areas

- Linux Security Modules (LSM) and BPF LSM;
- AppArmor and mandatory access control;
- eBPF tracing, Linux Audit, and system observability;
- endpoint detection and response, SIEM, and event correlation;
- provenance tracking and information-flow security;
- behavioral and sequence-based intrusion detection;
- capability systems, sandboxing, cgroups, namespaces, and seccomp;
- recurrent, state-space, and associative-memory models;
- policy compilation, decision caches, and runtime enforcement;
- security controls for autonomous software and AI agents.

## Project-specific position

Unix-AGB does not claim to invent Linux security hooks, mandatory access
control, behavioral detection, event stores, provenance, causal models, or
neural memory. Its proposed contribution is a particular integration pattern:

```text
Linux events
→ normalized canonical evidence
→ bounded causal state per security namespace
→ explicit policy evaluation
→ compact deterministic enforcement policy
→ AppArmor / LSM / BPF / cgroups and related Linux controls
```

The kernel remains authoritative for identity, observation, and enforcement.
The neural or associative state is not canonical evidence and cannot grant a
permission prohibited by base policy. LLMs, when used, remain outside the hot
path and may explain authorized evidence but do not become enforcement
authorities.

## Aletheion lineage

The architecture builds on work developed in the Aletheion project family:

- **ASM-CM — Aletheion Compact Memory Model** supplies the research basis for
  bounded persistent causal/associative state;
- **ASM Memory Bridge / Aletheion Memory Runtime** supplies separation between
  associative state, canonical payloads, authorization, provenance, readers,
  isolated namespaces, and fail-closed restoration;
- **Aletheion Guard Bridge (AGB)** applies those principles to Linux security
  events and policy compilation.

Component results from ASM-CM are prior evidence, not proof that the same
compactness, accuracy, latency, or endurance will hold for operating-system
security workloads. Unix-AGB must establish those properties independently.

## Linux and security foundations

Unix-AGB is designed to reuse Linux, Ubuntu, AppArmor, LSM, BPF/eBPF, cgroups,
namespaces, systemd, seccomp, and related mechanisms. Those technologies are
independent prior work and retain their own authorship and licensing terms.
Using them does not imply endorsement by their maintainers or vendors.

## Non-claims

This project does not claim:

- invention of the underlying Linux, LSM, BPF, AppArmor, or Ubuntu mechanisms;
- universal malware detection or prevention;
- that a neural state is a lossless copy of event history;
- production readiness, formal non-interference, or complete isolation;
- security against a hostile kernel, firmware, hardware, or hypervisor;
- that current architecture documents describe an already implemented system;
- that “Unix-AGB” is UNIX® certified or authorized to use the UNIX trademark as
  a product designation.

## Citation and disclosure

Research and derivative work should cite this repository and identify which
components, contracts, policies, experiments, and Aletheion technologies are
reused or modified. Comparisons must distinguish architecture proposals,
implemented controls, component-level evidence, and end-to-end validated
results.
