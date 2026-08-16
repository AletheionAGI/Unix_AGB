# Etapa 53 — prova dupla pós-restart concluída

Execução no laboratório registrou quatro eventos em cada política, antes e
depois da reinicialização do admin server:

| Política | A antes/depois | B antes/depois |
|---|---|---|
| UID + GID | aceita / aceita | rejeitada / rejeitada |
| Somente GID | aceita / aceita | aceita / aceita |
| Somente UID | aceita / aceita | rejeitada / rejeitada |

Os 12 eventos JSONL preservam a identidade derivada de `SO_PEERCRED`. A
configuração de autorização foi reaplicada após o restart sem alterar a
semântica de aceitação ou rejeição.

Próximo passo: simular configuração ausente ou inválida e confirmar que o
admin server falha fechado.
