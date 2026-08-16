# Etapa 06 — Broker persistente Rust

Data: 2026-08-15

## Entrega

- daemon `agb-policy-broker` em Rust;
- socket Unix JSONL persistente;
- cache TTL de dois segundos por namespace/recurso/revisão;
- fallback `DENY` para requests inválidos ou efeitos desconhecidos;
- auditoria JSONL das respostas;
- registro separado com backend `seccomp-user-notify`.

## Execução

```bash
cargo run --bin agb-policy-broker -- var/agb-policy.sock var/enforcement.jsonl
```

## Limitações

O daemon fornece a fronteira persistente de política, mas ainda não recebe
diretamente o file descriptor do listener seccomp. A próxima integração deve
conectar o protocolo de notificações do kernel a este daemon e adicionar
supervisão de restart/health.

O harness seccomp já consegue encaminhar requests ao daemon Rust; a mediação do
fd do listener ainda permanece no adaptador Python de laboratório.
