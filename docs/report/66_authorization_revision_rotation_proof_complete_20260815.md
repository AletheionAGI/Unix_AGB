# Etapa 66 — prova de rotação de revisão concluída

Execução privilegiada aprovada. Em cada uma das três políticas, respostas e
audit logs registraram a sequência exata:

```text
lab-authz-v1, lab-authz-v1, lab-authz-v2, lab-authz-v2
```

As duas primeiras decisões ocorreram antes do restart; as duas últimas após o
restart. A rotação da revisão ficou explicitamente separada no histórico, sem
alterar as decisões esperadas de UID/GID.

Próximo passo: testar uma revisão ausente após restart com o modo fail-closed
ativo e confirmar rejeição segura.
