# Etapa 05 — Pipeline BPF → Gateway

Data: 2026-08-15

## Entrega

- pipeline síncrono entre normalizador BPF e `agb-gateway`;
- limite configurável de tamanho de linha;
- contadores de eventos aceitos, rejeitados e oversized;
- persistência no canonical store;
- relatório de throughput e backpressure;
- fixture textual BPF para reprodução.

## Execução

```bash
cargo build --quiet --bin agb-gateway
python3 scripts/run_bpf_gateway_pipeline.py \
  --input fixtures/events/bpf-sample.txt
```

## Limitações

O fixture usa PID 1 e serve apenas como contrato textual; coleta privilegiada
real depende de `bpftrace`/tracefs. O pipeline ainda não possui fila durável,
reconexão automática nem métricas Prometheus.

