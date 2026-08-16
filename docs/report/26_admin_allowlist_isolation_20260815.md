# Etapa 26 — Isolamento da allowlist administrativa

Data: 2026-08-15

## Entrega

- teste com UID deliberadamente fora da allowlist;
- peer recebe `peer-not-allowlisted` antes da operação;
- unidade systemd documenta `AGB_ADMIN_UIDS` e `AGB_ADMIN_GIDS` via env file.

## Limitações

O teste usa o mesmo usuário do processo com uma lista incompatível; ainda não
cria usuários/grupos Linux dedicados nem testa namespaces de usuário.

