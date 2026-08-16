# Etapa 27 — Probe de identidade Linux e user namespace

Data: 2026-08-15

## Entrega

- probe da UID/GID real do processo;
- detecção da disponibilidade de `unshare -Ur`;
- execução sem criar usuários persistentes;
- relatório distingue namespace suportado de bloqueio do host.

## Execução

```bash
python3 scripts/probe_linux_identity_namespace.py
```

## Limitações

O probe não cria contas Linux dedicadas nem altera grupos. A validação completa
exige um host de laboratório com dois usuários/grupos e permissões controladas.

