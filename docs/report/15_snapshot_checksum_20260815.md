# Etapa 15 — Checksum e versionamento do snapshot

Data: 2026-08-15

## Entrega

- entradas persistidas com `format_version: 1`;
- checksum determinístico sobre chave, efeito, revisão e expiração;
- restore rejeita formato desconhecido ou checksum inválido;
- entradas válidas continuam sujeitas ao TTL.

## Limitações

O checksum detecta corrupção acidental, mas não autentica contra um atacante.
Integridade criptográfica assinada é uma etapa posterior.
