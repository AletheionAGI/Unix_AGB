# Etapa 16 — Integridade SHA-256 do snapshot

Data: 2026-08-15

## Entrega

- checksum interno substituído por SHA-256;
- lockfile Rust atualizado;
- restore rejeita alteração deliberada de campos sem atualização do digest;
- formato continua versionado como `format_version: 1`.

## Limitações

SHA-256 detecta adulteração sem a chave de autenticação, mas não prova origem
nem fornece assinatura de atualização. Assinatura de artefatos e rotação de
chaves continuam pendentes.

