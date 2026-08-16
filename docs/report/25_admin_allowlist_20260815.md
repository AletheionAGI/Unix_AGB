# Etapa 25 — Allowlist de UID/GID

Data: 2026-08-15

## Entrega

- allowlist opcional `AGB_ADMIN_UIDS`;
- allowlist opcional `AGB_ADMIN_GIDS`;
- consulta de credenciais antes da operação;
- peer fora da allowlist recebe `peer-not-allowlisted`;
- auditoria preserva PID/UID/GID observados.

## Operação

```bash
AGB_ADMIN_UIDS=1000 AGB_ADMIN_GIDS=1000 \
  target/release/agb-admin-server ...
```

## Limitações

As listas são carregadas pelo processo. Alterações exigem restart controlado;
grupos dinâmicos e policy externa ainda não estão integrados.
