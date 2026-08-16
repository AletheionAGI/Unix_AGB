# Etapa 22 — Socket administrativo separado

Data: 2026-08-15

## Entrega

- daemon `agb-admin-server` em socket Unix dedicado;
- token validado no processo administrativo;
- operações `list` e `rotate`;
- rate limit de cinco requests por minuto;
- auditoria dedicada em JSONL;
- socket de enforcement permanece separado.

## Limitações

O rate limit é local ao processo e a identificação ainda é baseada no token,
sem identidade de operador. Integração systemd e credenciais por usuário ficam
para etapa posterior.

