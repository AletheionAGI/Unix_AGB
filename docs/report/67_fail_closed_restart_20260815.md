# Etapa 67 — fail-closed após restart

O cenário de allowlist ausente agora reinicia o admin server com
`AGB_ADMIN_FAIL_CLOSED_CONFIG=1` e exige `peer-not-allowlisted` antes e depois
do restart, com dois eventos persistidos no audit log.

Próximo passo: executar `make fail-closed-config` e revisar os dois eventos do
caso `absent`.
