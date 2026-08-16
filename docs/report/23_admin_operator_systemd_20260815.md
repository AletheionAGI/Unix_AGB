# Etapa 23 — Operador, systemd e rate limit

Data: 2026-08-15

## Entrega

- campo `operator` no protocolo administrativo;
- operador registrado em cada resposta/auditoria;
- unidade `unix-agb-admin.service` separada;
- teste confirma rate limit no sexto request em 60 segundos.

## Limitações

O identificador ainda é declarado pelo cliente e não substitui autenticação
por credenciais Unix, mTLS ou identidade externa.
