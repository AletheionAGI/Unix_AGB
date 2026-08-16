# Etapa 56 — allowlist malformada fail-closed

O teste `make fail-closed-config` agora executa dois casos: allowlist ausente e
`AGB_ADMIN_UIDS=not-a-uid`. Ambos exigem `peer-not-allowlisted` na resposta e
no audit log.

Próximo passo: testar token ausente ou inválido e confirmar rejeição auditável.
