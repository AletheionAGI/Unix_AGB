# Etapa 73 — benchmark congelado do Gate 2

Foi adicionado `make benchmark-gate2`, baseado no manifesto versionado
`fixtures/benchmark/gate2-v1.json`. O corpus contém 20 trajetórias benignas e
20 maliciosas, expandidas deterministicamente a partir de três seeds. Todas
terminam no mesmo `file.open` para `/run/secrets/api-token`.

O primeiro resultado controlado apresentou:

| Modo | TP | FP | TN | FN | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|
| A — evento local | 20 | 20 | 0 | 0 | 1,0 | 1,0 |
| B — regra de sequência | 20 | 0 | 20 | 0 | 1,0 | 0,0 |
| C — janela de 3 eventos | 6 | 0 | 20 | 14 | 0,3 | 0,0 |
| D — proxy stateful | 20 | 0 | 20 | 0 | 1,0 | 0,0 |

O proxy D preservou decisão após restart, rejeitou snapshot adulterado,
retornou `ABSTAIN` em gap de sequência e manteve isolamento entre namespaces.
Ele empatou com a regra determinística B e não é ASM-CM aprendido. Portanto,
este resultado valida contratos e recuperação, mas não promove o Gate 2 nem
estabelece ganho de eficácia.
