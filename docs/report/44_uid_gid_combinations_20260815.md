# Etapa 44 — combinações UID/GID

Adicionado `make uid-gid-combinations` com três casos explícitos:

- UID e GID simultaneamente allowlisted;
- contas distintas compartilhando GID;
- regra somente de UID.

O probe é não destrutivo e marca a matriz como `ready`; a execução com contas
reais compartilhando grupo deve ocorrer no mesmo host privilegiado controlado,
com criação temporária de usuários/grupos pelo harness.

Próximo passo: implementar a execução privilegiada dessas três variantes e
registrar cada decisão no audit log.
