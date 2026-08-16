# Etapa 08 — Supervisor do broker Rust

Data: 2026-08-15

## Entrega

- supervisor para `agb-policy-broker`;
- health check pela criação do socket Unix;
- restart com backoff configurável;
- limite de tentativas;
- encerramento por SIGTERM/SIGINT;
- remoção do socket órfão no encerramento.

## Execução

```bash
python3 scripts/supervise_policy_broker.py \
  --socket var/agb-policy.sock \
  --audit var/enforcement.jsonl
```

## Limitações

O supervisor ainda não possui endpoint de health protocolar, readiness JSON,
watchdog de latência ou integração systemd. O próximo passo é mover o
supervisor para uma unidade systemd dedicada e testar crash/restart durante uma
notificação seccomp ativa.

