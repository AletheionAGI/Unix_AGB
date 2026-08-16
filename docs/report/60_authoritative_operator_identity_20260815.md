# Etapa 60 — identidade autoritativa do operador

O campo `operator` fornecido pelo cliente foi removido de `Request`. A
identidade gravada nas respostas e no audit log vem exclusivamente de
`SO_PEERCRED` (`pid`, `uid`, `gid`).

JSON com o campo legado continua aceito por compatibilidade do desserializador,
mas não influencia autorização nem auditoria.

Próximo passo: adicionar testes explícitos de spoofing para demonstrar que um
campo `operator` falsificado não altera o registro autoritativo.
