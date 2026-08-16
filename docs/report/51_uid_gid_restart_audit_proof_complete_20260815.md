# Etapa 51 — prova UID/GID com restart concluída

Execução privilegiada confirmou as três políticas antes e depois do restart:

| Política | Conta A `994:971` | Conta B `993:971` | Após restart |
|---|---|---|---|
| UID + GID | aceita | rejeitada | A aceita |
| Somente GID | aceita | aceita | A aceita |
| Somente UID | aceita | rejeitada | A aceita |

Foram persistidos nove eventos JSONL, três por variante. A identidade de cada
cliente foi derivada de `SO_PEERCRED`, e a configuração de autorização foi
aplicada novamente quando o admin server reiniciou.

Próximo passo: testar falha de leitura/ausência da configuração de autorização
e confirmar fallback fail-closed.
