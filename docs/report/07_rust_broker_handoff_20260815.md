# Etapa 07 — Handoff para o broker Rust

Data: 2026-08-15

## Entrega

- harness seccomp encaminha requests para `agb-policy-broker` via socket Unix;
- decisão causal continua vindo do `agb-gateway`;
- daemon Rust resolve cache e fallback;
- resposta Rust controla a resposta enviada à notificação seccomp;
- relatório identifica o backend composto `seccomp-user-notify+rust-policy-broker`.

## Verificação

`make seccomp-proof` passou com duas tentativas benignas e duas suspeitas. A
segunda tentativa suspeita retornou `cache_hit: true` e `EACCES`.

## Limitação

O fd do listener seccomp ainda é mediado pelo adaptador Python do laboratório.
O próximo passo é mover essa mediação para Rust e adicionar health/restart
supervisionados.

