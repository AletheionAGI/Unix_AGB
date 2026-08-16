# Etapa 03 — Cache e fallback do broker

Data: 2026-08-15

## Entrega

- cache de decisões versionado por revisão de política e TTL;
- segunda notificação seccomp reutilizando a decisão cacheada;
- timeout de 2 segundos para gateway e listener;
- fallback `DENY` quando o gateway não responde;
- validação de `notification_id`;
- registro externo `seccomp-user-notify` separado do backend fake.

## Verificação

`make seccomp-proof` passou com duas tentativas consecutivas:

- trajetória benigna: dois acessos permitidos;
- trajetória suspeita: dois acessos negados com `EACCES`;
- `cache_hit: true` na segunda tentativa.

## Limitações

O broker ainda é um harness Python de laboratório. A migração para daemon Rust,
restart supervisionado real e observer BPF integrado permanecem nas próximas
etapas.

