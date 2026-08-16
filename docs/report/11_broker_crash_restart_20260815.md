# Etapa 11 — Crash/restart do broker

Data: 2026-08-15

## Entrega

- teste mata o broker com `SIGKILL`;
- confirma que o socket antigo desaparece;
- reinicia uma nova instância;
- confirma health protocolar após restart;
- executa tudo em diretório temporário.

## Execução

```bash
cargo build --quiet --bin agb-policy-broker
python3 scripts/test_broker_restart.py
```

## Limitações

O teste ainda não verifica uma notificação seccomp pendente durante o crash nem
persiste a cache entre processos. Essas são as próximas condições de promoção.

