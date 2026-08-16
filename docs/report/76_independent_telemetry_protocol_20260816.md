# Etapa 76 — protocolo de telemetria independente

Foi implementado o contrato para receber trajetórias coletadas fora do runner
de benchmark, com proveniência real (`ptrace`, `bpf`, `audit` ou
`agent-broker`), revisão do coletor, fonte externa do rótulo, família e split
pré-atribuído.

`make freeze-independent-corpus` valida e congela o SHA-256 do JSONL. O processo
falha em:

- proveniência sintética;
- eventos ou namespaces duplicados entre splits;
- gap de sequência;
- múltiplos namespaces na mesma trajetória;
- `event_id` reutilizado;
- campos desconhecidos ou metadados de rotulagem ausentes.

O runner multi-seed pode receber `--independent-dataset` e avalia somente o
split `test`. Um corpus só se torna elegível para promoção com pelo menos 20
trajetórias benignas, 20 maliciosas e três famílias no teste.

Nenhum resultado de eficácia foi produzido nesta etapa: o repositório fornece
o protocolo, mas não inventa telemetria “real”. A próxima dependência é uma
coleta autorizada e rotulagem independente congelada antes da execução.
