# Etapa 77 — falsos positivos externos multi-seed

Uma captura BPF `system-wide` de 10 segundos foi revisada integralmente antes
da avaliação. O corpus congelado contém 50 trajetórias benignas e 7.616 eventos,
com SHA-256
`deab550cd06f1590e094256f2184deaf1d95729b4922052357ef5bdeb5e8b548`.
O split de teste contém 37 trajetórias e 5.307 eventos: 30 rótulos de confiança
alta e sete de confiança baixa.

Três checkpoints promovidos `asm_c2_fw_lm_confirmation` foram executados em uma
NVIDIA GeForce RTX 4090 com PyTorch 2.13.0+cu130 e código ASM na revisão
`4c8eddf2f07d9aec800769323d7e1effbd64815a`.

## Resultado

| Motor | TN | FP | Abstain | Cobertura | FPR |
|---|---:|---:|---:|---:|---:|
| A — evento local | 37 | 0 | 0 | 1,00 | 0,00 |
| B — regra de sequência | 37 | 0 | 0 | 1,00 | 0,00 |
| C — janela deslizante | 37 | 0 | 0 | 1,00 | 0,00 |
| ASM-CM seed 1 | 37 | 0 | 0 | 1,00 | 0,00 |
| ASM-CM seed 2 | 37 | 0 | 0 | 1,00 | 0,00 |
| ASM-CM seed 3 | 37 | 0 | 0 | 1,00 | 0,00 |

Todos os seeds classificaram corretamente os 30 itens de confiança alta e os
sete de confiança baixa. Não houve divergência de resultado entre famílias.

Uma execução anterior mostrou 17 abstenções porque janelas derivadas do mesmo
processo reiniciavam `sequence` em 1 enquanto o motor preservava o namespace.
Esse número coincidia exatamente com as 17 janelas de continuação. O runner foi
corrigido para usar `provenance.source_sequence`, e abstenção deixou de ser
contabilizada como verdadeiro negativo. O resultado desta etapa é a execução
corrigida.

## Custo observado

| Seed | Inferência p50 | p95 | p99 | CUDA alocada máx. | CUDA reservada máx. |
|---:|---:|---:|---:|---:|---:|
| 1 | 20,07 ms | 51,13 ms | 67,01 ms | 387.714.560 B | 522.190.848 B |
| 2 | 20,37 ms | 51,27 ms | 67,93 ms | 388.630.016 B | 522.190.848 B |
| 3 | 20,54 ms | 51,14 ms | 67,90 ms | 388.630.016 B | 522.190.848 B |

Os 5.307 eventos acionaram atualização neural. O p50 do baseline de sequência
foi 1,275 µs, aproximadamente quatro ordens de grandeza menor. Portanto, o
resultado reforça que ASM-CM não deve participar sincronicamente de toda syscall:
inferência deve ser seletiva ou agrupada, e o hot path deve consumir política
determinística pré-computada.

## Limitações

Este corpus mede somente falso positivo sobre atividade externa rotulada como
benigna. Ele não contém trajetória maliciosa nem workload protegido, não mede
recall e não é elegível para promoção do Gate 2. Os rótulos continuam sujeitos
a viés do coletor e do revisor. Destinos de rede estavam ausentes em parte da
captura, justificando os sete rótulos de baixa confiança.
