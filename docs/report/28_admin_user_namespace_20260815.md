# Etapa 28 — Admin server em user namespace

Data: 2026-08-15

## Entrega

- admin server iniciado com `unshare -Ur`;
- cliente externo conecta ao socket Unix;
- allowlist usa UID real do host;
- UID virtual `0` deve ser recusado quando não corresponde à allowlist real;
- relatório de credenciais e decisão produzido pelo probe.

## Limitações

O comportamento depende do mapeamento de credenciais do kernel e das políticas
do host. O probe não cria usuários persistentes nem testa múltiplos grupos reais.
