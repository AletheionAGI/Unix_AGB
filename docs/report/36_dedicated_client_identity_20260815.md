# Etapa 36 — cliente com identidade dedicada

Corrigida a rejeição observada no laboratório: o servidor estava corretamente
limitado ao UID/GID temporário, mas o cliente do harness era executado como
root.

Foi adicionado `scripts/admin_request.py`; agora a requisição autenticada é
enviada via `runuser` usando a mesma conta dedicada, validando a identidade do
cliente e a allowlist ponta a ponta.

Próximo passo: repetir o harness e verificar `admin-ok` e o audit log JSONL.
