# Etapa 80 — motor de política Gate 3 em dry-run

Foi implementado um recorte independente de enforcement para transformar
`SecurityEvent` mais `SecurityStateSummary` em decisão auditável e, somente para
restrições, em cache determinístico de curta duração.

## Semântica

O avaliador valida contratos, revisão de política, namespace exato e revisão de
estado. `restricted` e `quarantined` acionam invariante `DENY`. Estado `elevated`
exige evidência, confiança mínima e fingerprint de modelo quando o engine é
ASM-CM. Estado ausente, desconhecido, obsoleto ou inconsistente produz
`ABSTAIN`. `normal` e `monitor` produzem `ALLOW` apenas como resultado shadow:
este primeiro recorte compila somente `DENY`, impedindo expansão de privilégio
derivada do modelo.

Falha de persistência da auditoria substitui o resultado por
`AUDIT_PERSISTENCE_UNAVAILABLE` e não popula o cache. O CLI sempre publica
`enforcement_applied: false`.

## Cache e recuperação

A chave liga namespace completo, operação e digest do recurso. A entrada liga
decision ID, revisão da política, revisão do estado, digest da evidência e
expiração. O snapshot usa HMAC-SHA-256, escrita temporária no mesmo diretório,
fsync, rename atômico e fsync do diretório. Testes cobrem reinício, adulteração,
expiração, revisão incompatível, estado obsoleto, rollback por limpeza e dois
namespaces com o mesmo PID e tempos de início diferentes.

O fixture `fixtures/gate3/dry-run-elevated.jsonl` passou pelo CLI real, gerando
um `DENY` causal, uma linha de auditoria, uma entrada autenticada e nenhuma ação
de enforcement.

## Lookup release

O microbenchmark `unix-agb-gate3-cache-lookup-v1`, com uma entrada e 100.000
hits em build release, mediu:

| Percentil | Faixa observada em duas execuções |
|---:|---:|
| p50 | 65 ns |
| p95 | 66–113 ns |
| p99 | 83–114 ns |

Essa medida isola apenas lookup em memória no mesmo processo. Não inclui IPC,
desserialização, syscall interceptada, auditoria ou backend de enforcement e não
deve ser apresentada como latência do sistema completo.

## Limites

O Gate 3 permanece protótipo dry-run. Ainda faltam política-base de produção,
distribuição de cache ao enforcement, credencial de HMAC fora de variável de
ambiente, observabilidade operacional e validação do caminho completo sob carga.
Nenhum resultado desta etapa promove o Gate 4.
