# Etapa 78 — promoção controlada multi-seed do Gate 2

O corpus protegido foi coletado por BPF a partir de processos reais e congelado
com SHA-256
`ae165d68603180df880de933ed8fb6a84137aac14cc1e8bdab65de259dd53740`.
Ele contém 180 trajetórias equilibradas e 1.260 eventos em três famílias:
origem administrativa, contexto de egressão credencial e origem de persistência.
O split congelado de teste contém 141 trajetórias (70 benignas, 71 maliciosas)
e 987 eventos. O manifesto declarou `promotion_eligible: true`.

Três checkpoints promovidos `asm_c2_fw_lm_confirmation` foram executados em uma
NVIDIA GeForce RTX 4090 com PyTorch 2.13.0+cu130 e código ASM na revisão
`4c8eddf2f07d9aec800769323d7e1effbd64815a`. O relatório integral produzido em
`var/benchmark/gate2-independent-multiseed.json` tinha SHA-256
`659e57647a9772f8926400a04321c6e27fc407c594e7ce0de28ae8a75b5f9770`.
O resumo versionado está em
`fixtures/benchmark/evidence/gate2-protected-multiseed-summary.json`.

## Resultado

| Motor | TN | FP | FN | TP | Acurácia | Recall |
|---|---:|---:|---:|---:|---:|---:|
| A — evento local | 44 | 26 | 46 | 25 | 48,94% | 35,21% |
| B — regra de sequência | 70 | 0 | 46 | 25 | 67,38% | 35,21% |
| C — janela deslizante | 70 | 0 | 46 | 25 | 67,38% | 35,21% |
| ASM-CM seed 1 | 70 | 0 | 0 | 71 | 100% | 100% |
| ASM-CM seed 2 | 70 | 0 | 0 | 71 | 100% | 100% |
| ASM-CM seed 3 | 70 | 0 | 0 | 71 | 100% | 100% |

Não houve abstenção nem divergência entre seeds. As três seeds foram não
inferiores e estritamente superiores à regra de sequência; portanto, o runner
registrou `gate2_promoted: true` segundo o critério congelado.

## Custo antes da otimização em lote

| Seed | Consulta p50 | p95 | p99 | CUDA alocada máx. | CUDA reservada máx. |
|---:|---:|---:|---:|---:|---:|
| 1 | 520,62 ms | 542,30 ms | 560,50 ms | 380.236.288 B | 432.013.312 B |
| 2 | 514,71 ms | 531,12 ms | 538,55 ms | 381.151.744 B | 432.013.312 B |
| 3 | 515,55 ms | 542,24 ms | 557,64 ms | 381.151.744 B | 432.013.312 B |

Esse custo não é aceitável no hot path. A promoção valida o runtime de estado e
a recuperação associativa no laboratório; não autoriza inferência síncrona em
syscalls nem promove Gate 3 ou Gate 4.

## Limitações e interpretação

As ações são controladas: rede somente loopback e arquivos inertes sob
`var/telemetry/protected-lab`. Rótulos semânticos de caminhos são parte da
política versionada e não contêm a classe revisada. Ainda assim, as famílias e o
vocabulário do adaptador foram projetados para este teste. Os 46 falsos negativos
dos baselines B/C são exatamente as famílias de persistência e administração que
esses baselines congelados não modelam. O resultado demonstra recuperação
associativa sobre relações configuradas; não demonstra descoberta autônoma de
ataques desconhecidos nem eficácia em telemetria natural adversarial.

Durante a captura, 5.153 eventos de processos externos efêmeros não puderam ter
`/proc` normalizado após a saída. Todos os 180 PIDs protegidos foram reconciliados,
e o corpus protegido ficou completo; o ruído reforça a necessidade de filtragem
precoce para operação contínua.
