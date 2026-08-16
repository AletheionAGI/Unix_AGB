# Etapa 24 — Identidade por credenciais Unix

Data: 2026-08-15

## Entrega

- leitura de `SO_PEERCRED` no socket administrativo;
- auditoria registra PID, UID e GID reais do cliente;
- identidade declarada no JSON deixa de ser autoridade;
- fallback `peer:unknown` quando a consulta falha.

## Limitações

`SO_PEERCRED` identifica o processo local, mas não substitui autorização por
grupo, policy de usuários ou identidade remota. O próximo passo é aplicar uma
allowlist de UID/GID e testar isolamento entre usuários.
