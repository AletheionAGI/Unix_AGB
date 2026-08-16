# Etapa 31 — harness privilegiado de identidade Linux

Foi adicionado `scripts/run_privileged_identity_harness.py` e o alvo
`make privileged-identity`.

O harness:

1. exige root e `AGB_RUN_PRIVILEGED_IDENTITY_TEST=1`;
2. cria uma conta de sistema temporária;
3. inicia `agb-admin-server` sob essa identidade via `runuser`;
4. aplica a allowlist de UID/GID real;
5. executa a matriz de identidade e verifica o caminho do audit log;
6. remove a conta temporária em um bloco `finally`.

Sem a variável explícita ou sem root, o resultado é `skipped` e nenhuma conta
do host é alterada. A execução privilegiada deve ocorrer somente em um host de
laboratório controlado.

Validação não privilegiada neste ambiente:

```text
make privileged-identity
status: skipped
```

Próximo passo: em laboratório, executar
`AGB_RUN_PRIVILEGED_IDENTITY_TEST=1 make privileged-identity` como root e
anexar o audit log com as decisões aceitas/rejeitadas.
