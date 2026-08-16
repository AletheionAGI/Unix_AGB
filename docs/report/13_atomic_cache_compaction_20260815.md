# Etapa 13 — Compactação atômica da cache

Data: 2026-08-15

## Entrega

- entradas expiradas são removidas no startup;
- snapshot válido é reescrito em arquivo `.compact`;
- `flush` seguido de `rename` atualiza o snapshot de forma atômica;
- cache restaurada continua disponível após compactação.

## Limitações

A durabilidade ainda depende do filesystem e não há `fsync` explícito do arquivo
e diretório. Isso deve ser tratado antes de uma promoção para produção.

