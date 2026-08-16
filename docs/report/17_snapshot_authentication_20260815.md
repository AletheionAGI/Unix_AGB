# Etapa 17 — Autenticação do snapshot

Data: 2026-08-15

## Entrega

- suporte a `AGB_CACHE_KEY` para HMAC-SHA256;
- digest registra o esquema (`hmac-sha256:` ou `sha256:`);
- restore rejeita digest produzido com chave diferente;
- modo sem chave permanece explícito como compatibilidade de laboratório.

## Operação

Em produção, iniciar o broker com uma chave secreta fornecida pelo ambiente:

```bash
AGB_CACHE_KEY='segredo-fora-do-repositório' \
  target/release/agb-policy-broker ...
```

A chave nunca é persistida no snapshot.

## Limitações

Ainda não há rotação de chaves nem armazenamento em um secret manager. A
rotação deve invalidar snapshots antigos de forma explícita.
