# Etapa 04 — Normalizador BPF

Data: 2026-08-15

## Entrega

- `scripts/bpf_to_events.py` transforma linhas `AGB_BPF` em `SecurityEvent`;
- identidade usa boot ID, PID e start time do processo;
- sequência é mantida por namespace;
- proveniência é marcada como `bpf`;
- operações suportadas: `process.exec`, `file.open` e `network.connect`;
- eventos desconhecidos ou processos encerrados são rejeitados com diagnóstico.

## Verificação

O teste usa a identidade do processo Python corrente e valida schema semântico,
proveniência e sequência inicial.

## Limitações

O normalizador ainda é um processo separado do gateway e não instala filtros BPF
nem coleta eventos privilegiados sozinho. A próxima etapa deve ligar o fluxo
`bpftrace | bpf_to_events | agb-gateway` com backpressure e métricas de perda.

