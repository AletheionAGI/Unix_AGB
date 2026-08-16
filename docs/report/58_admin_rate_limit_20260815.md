# Etapa 58 — rate limit administrativo

Adicionado `make admin-rate-limit`. O teste envia seis requisições autenticadas
de um peer allowlisted; exige cinco `admin-ok`, uma `rate-limit` e a persistência
da rejeição no audit log.

Próximo passo: testar recuperação da janela de rate limit com relógio
controlável ou configuração de janela curta de laboratório.
