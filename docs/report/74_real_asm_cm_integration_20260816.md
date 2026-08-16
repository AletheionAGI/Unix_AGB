# Etapa 74 — integração real do ASM-CM

O modo D do benchmark congelado foi executado com o checkpoint promovido
ASM-CM seed 1 (`ASM-C2-FW-LM`), usando PyTorch 2.13 em uma NVIDIA GeForce RTX
4090 com 24.564 MiB.

- checkpoint SHA-256:
  `96293688518fc0a2e83525af6ad28d16f39677980432762328bf4ad8aac654de`;
- revisão do código ASM:
  `4c8eddf2f07d9aec800769323d7e1effbd64815a`;
- corpus: 40 trajetórias e 172 eventos, manifesto SHA-256
  `f617bcce0b1adb99fb93dd187c5ba5ba988b49ee0656cc324b27e70e6466fe38`.

## Resultado

| Modo | TP | FP | TN | FN | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|
| A — evento local | 20 | 20 | 0 | 0 | 1,0 | 1,0 |
| B — regra de sequência | 20 | 0 | 20 | 0 | 1,0 | 0,0 |
| C — janela de 3 eventos | 6 | 0 | 20 | 14 | 0,3 | 0,0 |
| D — ASM-CM real | 20 | 0 | 20 | 0 | 1,0 | 0,0 |

O ASM-CM selecionou o `event_id` de `network.connect`; uma política
determinística transformou a presença dessa evidência em `DENY`. No smoke test,
a confiança da recuperação maliciosa foi aproximadamente 0,9988. Estado real
foi salvo em 146.741 bytes, restaurou a mesma decisão após restart e rejeitou
adulteração pelo checksum.

No benchmark em GPU, o modo D apresentou p50 de aproximadamente 5,08 ms e p99
de aproximadamente 522 ms por atualização; a cauda inclui consultas MQAR com
padding até o comprimento mínimo de treinamento. `tracemalloc` não mede os
pesos e alocações nativas do PyTorch, portanto seu número não deve ser usado
como RSS total.

O ASM-CM empatou com a regra B neste corpus sintético. Isso comprova integração
e recuperação de evidência, mas não vantagem de segurança, generalização ou
prontidão para enforcement. A promoção continua bloqueada até avaliação
multi-seed e workload de segurança independente.
