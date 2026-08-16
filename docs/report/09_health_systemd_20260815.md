# Etapa 09 — Health protocolar e systemd

Data: 2026-08-15

## Entrega

- `check_policy_broker_health.py` faz uma requisição real ao socket;
- valida schema mínimo, backend e fallback da resposta;
- unidade systemd com restart-on-failure e sandboxing básico;
- caminhos separados para socket e auditoria.

## Limitações

A unidade é um template de laboratório e ainda requer instalação em `/opt` e
criação dos diretórios de runtime. O health check usa uma requisição de probe,
não um endpoint dedicado. A próxima etapa deve adicionar `type: health` ao
protocolo e testar crash/restart com systemd em um host Ubuntu descartável.

