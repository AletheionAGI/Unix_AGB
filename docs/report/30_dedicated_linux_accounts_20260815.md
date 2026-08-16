# Etapa 30 — contas e grupos Linux dedicados

Foi adicionado `scripts/test_admin_dedicated_accounts.py` e o alvo
`make dedicated-accounts`. O probe consulta uma conta Linux existente (`nobody`)
e seu grupo primário, verifica ferramentas de troca de identidade e informa se
o host está preparado para executar a matriz administrativa com um UID/GID real.

O probe não cria nem remove contas no host. Em uma máquina sem privilégio de
root, ele registra `skipped` com a razão explícita; em um laboratório
controlado, executado como root e com `runuser` ou `setpriv`, registra `ready`
para que o harness possa iniciar o servidor com a identidade dedicada e testar
allowlist de UID/GID, grupo divergente e namespace.

Validação realizada:

```text
make dedicated-accounts
```

Resultado esperado neste ambiente: `status: skipped`, sem mutações no banco de
contas do sistema. A matriz anterior (`make uid-gid-matrix`) continua sendo a
prova automatizada para a identidade do processo atual e user namespace.

Próximo passo: executar o harness privilegiado em um host de laboratório com
conta/grupo dedicados e capturar decisões aceitas e rejeitadas no audit log.
