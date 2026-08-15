# ADR-0001: Hybrid Rust/Python runtime

Status: accepted for Gate 0
Date: 2026-08-15

## Decision

- Rust owns event validation, canonical append, namespace sequencing, policy
  dry-run, fake enforcement, and `agbctl`.
- Python owns the isolated fake ASM service and is the future integration seam
  for ASM-CM/PyTorch.
- Processes communicate locally through a Unix domain socket with JSONL during
  Gate 0.
- Public contracts are JSON Schema 2020-12 under `schemas/v1/`.
- Canonical persistence begins as append-only JSONL. SQLite remains a candidate
  after measured requirements are available.

## Rationale

Rust provides memory safety and a suitable path toward privileged Linux-facing
components. Python preserves compatibility with the current ASM/PyTorch
research stack. A process boundary prevents the model runtime from inheriting
collector or enforcer privileges.

## Consequences

- two toolchains and cross-language contract tests are required;
- JSONL is inspectable but not an optimized production protocol;
- the model process can fail independently and must cause abstention;
- a future binary protocol requires a new ADR and compatibility plan.
