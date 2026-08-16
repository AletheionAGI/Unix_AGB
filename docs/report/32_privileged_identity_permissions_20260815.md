# Etapa 32 — permissões do harness privilegiado

Corrigida a falha observada ao executar o harness com `sudo`: usuários
temporários e processos em user namespace não conseguiam atravessar o caminho
privado `/home/felipe/...` até `target/debug/agb-admin-server`.

Agora a matriz e o harness copiam o binário para o diretório temporário da
execução e aplicam modo executável antes de iniciar `runuser` ou `unshare`.
Assim, o teste não depende das permissões dos diretórios-pai do workspace.

Próximo passo: repetir `sudo AGB_RUN_PRIVILEGED_IDENTITY_TEST=1 make
privileged-identity` e validar as linhas aceitas/rejeitadas no audit log.
