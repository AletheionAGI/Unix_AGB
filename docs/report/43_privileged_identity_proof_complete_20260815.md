# Etapa 43 — prova privilegiada concluída

Execução confirmada no host de laboratório:

- conta allowlisted: UID `994`, GID `971` → `admin-ok`;
- conta outsider: UID `993`, GID `970` → `peer-not-allowlisted`;
- audit log: `2` eventos JSONL;
- operadores identificados por PID, UID e GID.

Esta etapa demonstra, com contas Linux reais, que a decisão administrativa
distingue identidades allowlisted e não allowlisted e persiste ambas as
decisões no audit log.

Próximo passo: repetir a mesma prova com grupos compartilhados e regras
simultâneas de UID/GID para cobrir combinações de autorização.
