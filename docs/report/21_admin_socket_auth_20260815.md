# Etapa 21 — Autorização no socket administrativo

Data: 2026-08-15

## Entrega

- protocolo `type: "admin"` no daemon Rust;
- validação de `AGB_ADMIN_TOKEN` no próprio broker;
- operações `list` e `rotate`;
- token inválido retorna fallback `DENY`;
- rotação limpa a cache em memória e move o snapshot para `.rotated`;
- auditoria continua registrada pelo broker.

## Limitações

O token ainda é compartilhado por ambiente e não há identidade por operador,
rate limit ou canal administrativo separado. Essas proteções ficam para uma
etapa posterior.
