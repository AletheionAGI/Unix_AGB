# Etapa 42 — captura dos eventos de auditoria

O harness agora inclui todos os eventos JSONL no resultado `status: passed`,
além das respostas individualizadas. Assim a execução privilegiada captura
diretamente:

1. decisão `admin-ok` da conta dedicada;
2. decisão `peer-not-allowlisted` da conta outsider.

Execute:

```bash
sudo AGB_RUN_PRIVILEGED_IDENTITY_TEST=1 make privileged-identity
```

Próximo passo: usar a saída `audit_events` como evidência anexada da prova.
