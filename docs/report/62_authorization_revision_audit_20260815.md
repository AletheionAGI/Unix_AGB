# Etapa 62 — revisão de autorização no audit log

As respostas e eventos administrativos agora incluem `authorization_revision`.
O valor vem de `AGB_ADMIN_AUTHZ_REVISION`; na ausência da variável, o servidor
usa `default-v1`. Isso permite correlacionar cada decisão ao conjunto de
configuração de autorização aplicado.

Próximo passo: testar uma revisão configurada explicitamente e sua permanência
após reinicialização do admin server.
