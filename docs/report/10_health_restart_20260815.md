# Etapa 10 — Health nativo e recuperação

Data: 2026-08-15

## Entrega

- request protocolar `type: "health"` no broker Rust;
- resposta `reason: "health-ok"`;
- health check atualizado para usar o tipo dedicado;
- teste de integração inicia o broker, consulta health e encerra o processo.

## Limitações

O teste de crash/restart ainda é executado pelo supervisor de laboratório, não
por uma unidade systemd real. A persistência da cache após restart continua
fora do escopo até haver uma política de snapshot definida.
