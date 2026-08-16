# Etapa 45 — status da matriz UID/GID

Execução confirmada:

- identidade allowlisted real: `admin-ok`;
- identidade outsider real: `peer-not-allowlisted`;
- audit log: dois eventos persistidos.

O alvo `uid-gid-combinations` confirmou a definição dos três casos, mas ainda
não executa contas distintas compartilhando um grupo nem a variante somente de
UID. Esses dois casos permanecem pendentes de implementação no harness
privilegiado.

Próximo passo: criar grupo temporário compartilhado, iniciar servidores com
allowlist somente de GID e somente de UID, e persistir os seis resultados no
audit log.
