# Unix-AGB Threat Model

Status: Gate 0 baseline
Last updated: 2026-08-15

## Security objective

Unix-AGB (Aletheion Guard Bridge, AGB) is intended to add trajectory-aware
restrictions to existing Linux security controls without making associative
state or a language model authoritative. The initial implementation is
audit-only and cannot block, kill, freeze, quarantine, or expand privileges.

## Assets

- kernel-derived subject identity and event provenance;
- canonical security events and their ordering;
- per-namespace causal state;
- policy definitions, revisions, and compiled decisions;
- checkpoint fingerprints and snapshots;
- authorization metadata and sensitive evidence;
- local control sockets and administrative commands;
- audit records needed to explain or reproduce a decision.

## Trust boundaries

```text
untrusted applications / synthetic producers
                    │
                    ▼ validation boundary
AGB Event Gateway ──→ Canonical Event Store
        │                        │
        ▼                        ▼ authorization boundary
ASM runtime                  Policy runtime
        └─────────────┬──────────┘
                      ▼ privilege boundary
              Enforcement adapter
                      │
                      ▼
             Linux security controls
```

The Gate 0 fake ASM runtime and fake enforcer are explicitly unprivileged. A
future collector/enforcer will cross a kernel privilege boundary and must be
isolated from the model runtime.

## Adversaries in scope

- compromised unprivileged process emitting malformed or adversarial events;
- malware attempting event flooding, replay, ordering gaps, or state poisoning;
- user or agent attempting to read another namespace or tenant;
- compromised container attempting identity or namespace confusion;
- prompt injection or tool abuse against an AI-agent integration;
- attacker replacing a checkpoint, snapshot, policy, or canonical event file;
- reader or administrator requesting more evidence than authorized;
- crashes and partial writes that could make restored state inconsistent.

## Out of scope for the initial gates

- an attacker controlling the host kernel, firmware, hardware, or hypervisor;
- complete defense against rootkits or hardware side channels;
- formal proof of non-interference;
- automatic classification of arbitrary malware;
- production enforcement or availability guarantees.

## Required invariants

1. Base Linux policy always has higher authority than AGB state.
2. AGB state may only maintain or reduce effective privileges.
3. Canonical evidence is never replaced by an associative summary.
4. Authorization is checked before resolving evidence.
5. Namespace keys include a stable discriminator; PID alone is invalid.
6. Replay, duplicate event IDs, and regressing sequence numbers are rejected.
7. Missing evidence produces `ABSTAIN`, not an invented explanation.
8. Incompatible or corrupt state cannot broaden privilege.
9. Failure of the model runtime leaves base policy operational.
10. The audit-only gate never invokes a real enforcement backend.

## Threats and initial mitigations

| Threat | Gate 0 mitigation | Future hardening |
|---|---|---|
| malformed event | schema and semantic validation | fuzzing at collector boundary |
| replay or duplicate | event-ID and sequence tracking | monotonic durable cursor |
| PID reuse | boot ID + PID + start time identity | kernel-derived identity token |
| cross-namespace read | exact namespace match | authorization policy and labels |
| event flood | bounded line/event size | bounded queues and per-source limits |
| partial canonical write | append + flush per record | checksums, fsync policy, WAL |
| state poisoning | audit-only effect and explicit signals | adversarial training and rate limits |
| compromised model | model output cannot grant | process sandbox and signed checkpoint |
| policy rollback | revision included in decisions | signed revisions and atomic maps |
| explanation injection | no LLM in Gate 0 | minimal authorized evidence packages |

## Fail-safe behavior

- Invalid input is rejected before canonical append.
- Duplicate/replayed input does not update state.
- Missing ASM runtime produces an `ABSTAIN` summary and audit decision.
- Store or state failure terminates the affected operation and does not call an
  enforcement backend.
- Recovery never infers that absence of state means permission.

## Review trigger

This model must be reviewed before adding eBPF/LSM collection, privileged
systemd units, remote APIs, real enforcement, checkpoint loading, or external
evidence readers.
