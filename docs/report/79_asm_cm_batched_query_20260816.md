# Etapa 79 — consulta ASM-CM vetorizada

Após a promoção controlada registrada na etapa 78, o adaptador snapshot-v4 foi
alterado para conservar um histórico causal compacto e executar uma única
avaliação vetorizada na consulta. O caminho anterior clonava o estado streaming
e reconstruía o preenchimento MQAR com aproximadamente 40 chamadas sequenciais
a `decode_step`.

O histórico é limitado aos últimos 64 pares relação/valor, igual à capacidade
de valores endereçáveis do adaptador. Eventos de origem não executam o modelo;
eles atualizam somente estado canônico e evidência. A consulta continua fora do
hot path determinístico e não concede privilégios.

## Equivalência

Comparações diretas entre o caminho streaming anterior e o novo forward em lote
produziram o mesmo token previsto e a mesma confiança para as três relações. Um
benchmark integral em CPU sobre o mesmo split protegido preservou, nas três
seeds, a matriz `TN=70, TP=71, FP=0, FN=0, abstain=0` e
`gate2_promoted: true`. Restauração de snapshot v4 preservou a evidência e a
decisão após reinício.

## Latência CPU

| Seed | Consulta p50 | p95 | p99 | Inferências |
|---:|---:|---:|---:|---:|
| 1 | 62,50 ms | 98,35 ms | 137,15 ms | 141 |
| 2 | 64,75 ms | 86,79 ms | 140,80 ms | 141 |
| 3 | 67,76 ms | 96,09 ms | 153,40 ms | 141 |

No teste isolado seed 1, a mesma consulta caiu de 1,25–1,52 s para 54–98 ms,
um ganho de 13–25× em CPU. O número de inferências no benchmark caiu de 212
(origens mais consultas) para 141 (somente consultas).

## Medição CUDA

Uma execução posterior na NVIDIA GeForce RTX 4090 preservou, nas três seeds, a
matriz `TN=70, TP=71, FP=0, FN=0, abstain=0`, cobertura integral e
`gate2_promoted: true`. O relatório
`var/benchmark/gate2-independent-multiseed-batched.json` tinha SHA-256
`458100b3a185a6265f1e0d3db8769988e820325007ea92c52fb342dfc1859830`.

| Seed | Consulta p50 | p95 | p99 | CUDA alocada máx. | CUDA reservada máx. |
|---:|---:|---:|---:|---:|---:|
| 1 | 23,48 ms | 24,86 ms | 28,13 ms | 370.268.160 B | 396.361.728 B |
| 2 | 22,99 ms | 23,87 ms | 24,60 ms | 371.707.904 B | 396.361.728 B |
| 3 | 22,90 ms | 24,15 ms | 24,73 ms | 371.707.904 B | 396.361.728 B |

Comparado à etapa 78, o p50 de consulta melhorou aproximadamente 22× e o
número de inferências caiu de 212 para 141 (33,5%). A reserva máxima CUDA caiu
de 432.013.312 B para 396.361.728 B. O resumo versionado está em
`fixtures/benchmark/evidence/gate2-protected-multiseed-batched-summary.json`.

Apesar do ganho, aproximadamente 23 ms ainda é muito superior ao baseline
determinístico de microssegundos. Portanto, a conclusão arquitetural não muda:
o hot path de enforcement deve usar decisões determinísticas pré-computadas; a
consulta neural permanece assíncrona ou fora da syscall bloqueada.
