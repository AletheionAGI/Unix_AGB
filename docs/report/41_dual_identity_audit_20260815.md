# Etapa 41 — auditoria das duas identidades

O resultado do laboratório confirmou:

- conta dedicada `994:971`: `admin-ok`;
- conta outsider `993:970`: `peer-not-allowlisted`.

O harness foi ajustado para enviar ambas as requisições antes de ler o audit
log. Agora exige pelo menos dois registros e confirma a presença das duas
decisões no JSONL.

Próximo passo: repetir o harness e capturar o audit log com os dois eventos.
