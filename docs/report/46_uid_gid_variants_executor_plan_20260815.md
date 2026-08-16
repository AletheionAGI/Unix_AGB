# Etapa 46 — executor das variantes UID/GID

O probe de combinações foi atualizado para deixar explícito que a execução
real depende do harness privilegiado e de contas temporárias controladas. A
matriz cobre:

- UID+GID simultâneos;
- somente GID compartilhado;
- somente UID.

As duas últimas variantes ainda requerem um executor dedicado que crie o grupo
compartilhado, lance instâncias separadas do servidor e consolide os eventos de
auditoria.

Próximo passo: implementar esse executor privilegiado, mantendo a criação e
remoção de usuários condicionadas a `AGB_RUN_PRIVILEGED_IDENTITY_TEST=1`.
