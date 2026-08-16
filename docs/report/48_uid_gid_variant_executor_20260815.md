# Etapa 48 — executor UID/GID

Implementado `scripts/run_uid_gid_variants.py` e o alvo `make uid-gid-variants`.
Em laboratório, com `AGB_RUN_UID_GID_VARIANTS=1` e root, o executor cria duas
contas com GID compartilhado e testa três instâncias: UID+GID, somente GID e
somente UID. Cada resposta registra UID/GID e decisão.

Sem os privilégios e a variável explícita, o comando retorna `skipped` sem
alterar contas do sistema.

Próximo passo: executar `sudo AGB_RUN_UID_GID_VARIANTS=1 make uid-gid-variants`
e anexar os resultados ao audit log.
