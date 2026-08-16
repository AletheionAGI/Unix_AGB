# Evidence report index

The numbered files in this directory are an append-only engineering journal.
They preserve the sequence of laboratory changes, but this index is the
authoritative entry point for determining current status. Gate status itself
remains authoritative in `ROADMAP.md`.

## Foundation and causal pipeline

- reports 03–05: cache fallback, BPF normalization, and gateway pipeline;
- reports 06–18: Rust broker, supervision, restart, persistence, rotation, and
  snapshot integrity;
- reports 69–72: continuous BPF observation and the current BPF-to-broker
  request adapter.
- report 73: frozen Gate 2 A–D benchmark and persistent stateful-proxy proof.
- report 74: real promoted-checkpoint ASM-CM integration and seed-1 result.
- report 75: adversarial multi-seed ASM-CM evaluation with CUDA accounting.

## Administrative boundary

- reports 19–29: cache administration, socket separation, peer credentials,
  allowlists, namespaces, and the initial UID/GID matrix;
- reports 30–45: dedicated identities, storage permissions, outsider tests,
  audit capture, and privileged proof completion;
- reports 48–68: identity variants, restart proofs, malformed configuration,
  rate limiting, authoritative operator identity, authorization revisions, and
  allowlist rotation.

## Current interpretation

- Gate 0 is complete as a repository and contract foundation.
- Gate 1 and Gate 4 contain laboratory prototypes only.
- Reports marked “proof complete” establish only their narrowly stated test;
  they do not promote an entire Gate or establish production readiness.
- Gate 2 has deterministic and real ASM-CM integration prototypes. Security-
  specific multi-seed efficacy remains unvalidated. Gate 3 policy evaluation
  remains unimplemented.

New work should update this index when it changes the current interpretation;
small chronological reports may still be retained for reproducibility.
