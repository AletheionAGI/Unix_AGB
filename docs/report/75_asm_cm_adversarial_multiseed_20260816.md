# Etapa 75 — ASM-CM adversarial multi-seed

Três checkpoints promovidos e independentes do ASM-CM foram executados na RTX
4090 sobre o corpus congelado `gate2-adversarial-v2`. O corpus contém 60
trajetórias balanceadas, 1.222 eventos e seis famílias:

- execução limpa;
- rede confiável;
- risco seguido de reset confiável;
- risco separado da credencial por gap longo;
- rede confiável seguida de risco;
- riscos repetidos.

Cada trajetória usa de 8 a 24 distractors antes do acesso terminal à mesma
credencial. A regra determinística B foi atualizada para compreender rede
confiável e reset, evitando um baseline deliberadamente fraco.

## Resultado

| Motor | TP | FP | TN | FN | Acurácia |
|---|---:|---:|---:|---:|---:|
| A — evento local | 30 | 30 | 0 | 0 | 0,50 |
| B — sequência forte | 30 | 0 | 30 | 0 | 1,00 |
| C — janela de 3 eventos | 0 | 0 | 30 | 30 | 0,50 |
| ASM-CM seed 1 | 30 | 0 | 30 | 0 | 1,00 |
| ASM-CM seed 2 | 30 | 0 | 30 | 0 | 1,00 |
| ASM-CM seed 3 | 30 | 0 | 30 | 0 | 1,00 |

A média de acurácia ASM-CM foi 1,00, com desvio-padrão populacional zero. Todos
os seeds foram não inferiores à sequência, mas nenhum a superou estritamente.
O Gate 2 permanece não promovido segundo o critério congelado.

## Custo observado

| Seed | Ingest p50 | Query p50 | Query p99 | CUDA alocada máx. | CUDA reservada máx. |
|---:|---:|---:|---:|---:|---:|
| 1 | 8,60 ms | 348,46 ms | 455,35 ms | 378.715.648 B | 432.013.312 B |
| 2 | 8,62 ms | 351,38 ms | 468,19 ms | 379.631.104 B | 432.013.312 B |
| 3 | 8,54 ms | 349,28 ms | 458,70 ms | 379.631.104 B | 432.013.312 B |

As medições sincronizam CUDA antes e depois de cada atualização. Consultas
continuam fora do caminho síncrono de syscall; decisões compiladas devem chegar
ao enforcement por cache determinístico.

## Interpretação

O experimento demonstra retenção relacional longa, invalidação, isolamento por
namespace e estabilidade entre checkpoints. Não demonstra superioridade sobre
uma regra que já conhece exatamente a relação de risco. O próximo teste deve
usar telemetria independente, padrões não codificados diretamente na regra B e
rótulos definidos antes da avaliação.
