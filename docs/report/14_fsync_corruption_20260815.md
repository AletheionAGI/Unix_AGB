# Etapa 14 — Fsync e corrupção do snapshot

Data: 2026-08-15

## Entrega

- `sync_all` explícito no arquivo temporário da cache;
- `rename` atômico mantido;
- `sync_all` explícito no diretório após a substituição;
- teste com linha JSON corrompida no snapshot;
- broker continua respondendo ao health após ignorar corrupção.

## Limitações

O teste cobre corrupção sintática de uma linha, mas ainda não simula power loss
real nem verifica checksum de cada registro. Um checksum/versionamento do
snapshot é o próximo endurecimento recomendado.

