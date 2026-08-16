# Etapa 38 — identidade e audit log verificados

Resultado do laboratório:

- UID dedicado: `994`
- GID dedicado: `971`
- decisão: `admin-ok`
- operador observado: `uid:994:gid:971`
- audit log: criado e identificado pelo harness

O harness agora lê o JSONL, exige ao menos um registro e confirma que o último
registro contém o UID/GID da conta dedicada.

Próximo passo: testar uma segunda conta/grupo real não allowlisted e confirmar
`peer-not-allowlisted` no mesmo cenário privilegiado.
