# Security Policy

Unix-AGB is experimental security research. The repository currently contains
an audit-only skeleton and must not be treated as a production security control.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could expose private data,
cross a namespace boundary, bypass a policy invariant, corrupt canonical
evidence, or affect a privileged future collector/enforcer.

Report privately to:

```text
contact@aletheionagi.com
Subject: [Unix-AGB Security] concise issue title
```

Include, when possible:

- affected revision and environment;
- impact and required privileges;
- minimal reproduction;
- logs or traces with secrets removed;
- suggested mitigation;
- whether disclosure is already public.

Receipt will be acknowledged as capacity permits. No fixed response or bounty
SLA is promised at this research stage. Coordinated disclosure timing will be
agreed in writing when the issue is confirmed.

## Security boundaries

- The current fake enforcer has no authority to modify the host.
- Synthetic events are not kernel-attested evidence.
- JSONL storage is a development backend, not a tamper-proof ledger.
- No checkpoint, model, or external reader should be trusted by default.

See [THREAT_MODEL.md](THREAT_MODEL.md) for assets, adversaries, invariants, and
fail-safe requirements.
