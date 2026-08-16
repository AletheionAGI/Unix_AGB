# Etapa 51 — prova UID/GID com restart concluída

Execução privilegiada confirmou as três políticas antes e depois do restart:

| Política | Conta A `994:971` | Conta B `993:971` | Após restart |
|---|---|---|---|
| UID + GID | aceita | rejeitada | somente A testada e aceita |
| Somente GID | aceita | aceita | somente A testada e aceita |
| Somente UID | aceita | rejeitada | somente A testada e aceita |

Foram persistidos nove eventos JSONL, três por variante. A identidade de cada
cliente foi derivada de `SO_PEERCRED`, e a configuração de autorização foi
aplicada novamente quando o admin server reiniciou.

Próximo passo: testar as duas identidades após restart e comparar as decisões.
