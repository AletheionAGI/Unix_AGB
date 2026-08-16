# Etapa 54 — configuração de autorização fail-closed

Foi adicionado o modo `AGB_ADMIN_FAIL_CLOSED_CONFIG=1`. Quando ativo, o admin
server rejeita todo peer se nenhuma allowlist UID ou GID tiver sido configurada.
Uma allowlist presente porém inválida também não contém nenhum peer permitido e
portanto é recusada.

O comportamento permissivo anterior permanece apenas quando o modo explícito
não é ativado, preservando os harnesses de laboratório existentes.

Próximo passo: adicionar um teste de integração que inicia o servidor sem
allowlist em modo fail-closed e exige `peer-not-allowlisted`.
