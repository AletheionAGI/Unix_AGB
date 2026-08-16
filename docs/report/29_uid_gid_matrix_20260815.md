# Etapa 29 — Matriz UID/GID

Data: 2026-08-15

## Entrega

- caso host com UID/GID permitidos;
- caso host com GID incompatível;
- caso user namespace com UID/GID virtuais `0:0`;
- resultado esperado: permitir apenas o primeiro caso;
- teste não cria usuários permanentes.

## Limitações

A matriz ainda usa o usuário atual e um GID deliberadamente inexistente para o
caso negativo. Um teste de produção deve usar contas/grupos dedicados e
políticas de instalação controladas.
