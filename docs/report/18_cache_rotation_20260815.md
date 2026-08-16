# Etapa 18 — Rotação controlada da cache

Data: 2026-08-15

## Entrega

- `AGB_CACHE_ROTATE=1` invalida a cache anterior no startup;
- snapshot antigo é movido para `<cache>.rotated`;
- nenhum dado é apagado automaticamente;
- rotação pode acompanhar troca de `AGB_CACHE_KEY`;
- restauração manual permanece possível a partir do arquivo rotacionado.

## Execução

```bash
AGB_CACHE_ROTATE=1 target/release/agb-policy-broker \
  var/agb-policy.sock var/enforcement.jsonl var/policy-cache.jsonl
```

## Limitações

A rotação ainda é uma operação local de startup. Falta um comando administrativo
com autenticação, retenção configurável e teste de rollback automatizado.

