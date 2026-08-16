# Etapa 12 — Cache persistente de decisões

Data: 2026-08-15

## Entrega

- cache Rust carregada na inicialização;
- entradas persistidas em JSONL com revisão e expiração;
- entradas expiradas ignoradas no restore;
- novas decisões appendadas no snapshot;
- caminho configurável como terceiro argumento do broker.

## Execução

```bash
cargo run --bin agb-policy-broker -- \
  var/agb-policy.sock var/enforcement.jsonl var/policy-cache.jsonl
```

## Limitações

O snapshot é append-only e ainda não possui compactação nem checksum. A
próxima etapa deve testar restore após crash e garantir atomicidade/rotação do
arquivo de cache.

