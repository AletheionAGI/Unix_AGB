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

## Limitação

O sandbox não expõe CUDA. Esses números verificam equivalência e direção do
ganho, mas não substituem uma nova medição na RTX 4090. O relatório CUDA
otimizado deve ser gravado em arquivo separado da evidência pré-otimização e
comparado por matriz de confusão, cobertura, latência e memória.
