# Etapa 63 — revisão de autorização após restart

O executor privilegiado de variantes agora fixa
`AGB_ADMIN_AUTHZ_REVISION=lab-authz-v1` e exige que cada evento, inclusive os
posteriores ao restart, contenha exatamente essa revisão.

Próximo passo: executar a matriz privilegiada e confirmar a revisão em todos
os 12 eventos.
