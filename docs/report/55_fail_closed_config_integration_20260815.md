# Etapa 55 — integração fail-closed

Adicionado `make fail-closed-config`. O teste inicia `agb-admin-server` sem
`AGB_ADMIN_UIDS` ou `AGB_ADMIN_GIDS`, ativa o modo fail-closed, envia uma
requisição com token válido e exige `peer-not-allowlisted` tanto na resposta
quanto no único evento do audit log.

Próximo passo: testar allowlist malformada e confirmar o mesmo fallback.
