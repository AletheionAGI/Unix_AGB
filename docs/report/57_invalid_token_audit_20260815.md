# Etapa 57 — token inválido e ausente

O teste fail-closed agora cobre token inválido e token vazio com uma allowlist
válida para o peer atual. Ambos exigem `invalid-token-or-request` na resposta e
no audit log.

Próximo passo: testar rate limit e confirmar que a sexta requisição é auditada
como `rate-limit`.
