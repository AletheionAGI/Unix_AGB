# Etapa 50 — auditoria e reinicialização das variantes

O executor de variantes agora lê e retorna os audit logs JSONL por caso. Após
as duas requisições iniciais, ele encerra e reinicia o admin server com a mesma
configuração de allowlist, envia outra requisição allowlisted e exige `admin-ok`.

Cada variante precisa registrar no mínimo três eventos: duas identidades antes
do restart e uma identidade allowlisted depois dele.

Próximo passo: executar o alvo privilegiado e revisar `audit_events` para os
três casos.
