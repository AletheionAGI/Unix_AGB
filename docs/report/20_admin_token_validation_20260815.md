# Etapa 20 — Validação do admin token

Data: 2026-08-15

## Entrega

- `AGB_ADMIN_TOKEN_FILE` opcional para validação contra secret local;
- token vazio ou incorreto é recusado;
- operação só começa depois da validação;
- compatibilidade mantida para laboratório sem arquivo de segredo.

## Operação

```bash
install -m 0600 /dev/null /etc/unix-agb/admin.token
openssl rand -hex 32 > /etc/unix-agb/admin.token
export AGB_ADMIN_TOKEN_FILE=/etc/unix-agb/admin.token
export AGB_ADMIN_TOKEN="$(cat /etc/unix-agb/admin.token)"
```

## Limitações

A validação ainda é local ao `agb-cachectl`; o socket administrativo do daemon
ainda precisa exigir o mesmo segredo em uma etapa futura.
