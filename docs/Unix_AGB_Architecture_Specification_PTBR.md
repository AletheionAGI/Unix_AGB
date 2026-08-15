# Unix-AGB / Aletheion Guard Bridge

**Especificação arquitetural completa — proposta inicial**  
**Data:** 15 de agosto de 2026  
**Status:** proposta de arquitetura / documento de trabalho  
**Base do sistema:** Ubuntu Linux + Linux Security Modules + BPF/eBPF + AppArmor  
**Tecnologia de estado:** ASM-CM — Aletheion Compact Memory Model  
**Orquestração de memória:** ASM Memory Bridge / Aletheion Memory Runtime  
**Nome de trabalho da camada de segurança:** AGB — Aletheion Guard Bridge  
**Nome de trabalho da distribuição/protótipo:** Unix-AGB

> **Tese central:** o kernel continua responsável por observar e impor. O AGB mantém memória causal de segurança, contexto autorizado, proveniência e política. O caminho crítico de enforcement permanece determinístico e não depende de uma inferência neural síncrona a cada syscall.

---

## 1. Resumo executivo

Unix-AGB é uma proposta de sistema de segurança stateful para Linux construída sobre Ubuntu, sem reescrever um sistema operacional do zero. A arquitetura reutiliza o kernel Linux, drivers, systemd, rede, VFS, gerenciamento de memória, AppArmor e demais mecanismos maduros do Ubuntu. O componente novo é uma camada de segurança orientada por trajetória: **Aletheion Guard Bridge (AGB)**.

O AGB combina quatro funções:

1. **observação de eventos do sistema**, inicialmente por BPF/eBPF e interfaces existentes;
2. **estado causal compacto**, mantido por ASM-CM por entidade ou namespace;
3. **resolução de fatos, autorização e proveniência**, inspirada no ASM Memory Bridge;
4. **enforcement determinístico**, aplicado por mecanismos Linux como AppArmor/LSM e políticas locais pré-computadas.

O objetivo não é substituir o kernel, o gerenciador de memória, o banco de dados ou o sistema de controle de acesso existente. O objetivo é permitir que decisões de segurança considerem **a trajetória de comportamento** de processos, usuários, containers e agentes de IA, em vez de somente o evento corrente.

A evolução recomendada é incremental:

```text
Fase 0  Ubuntu normal + coleta e auditoria
Fase 1  AGB daemon + ASM-CM + Memory Bridge
Fase 2  enforcement por AppArmor/BPF-LSM/policy cache
Fase 3  proteção específica para agentes de IA
Fase 4  imagem Ubuntu derivada / AGB Developer Preview
Fase 5  kernel Ubuntu customizado somente se houver necessidade comprovada
```

A arquitetura do ASM Memory Bridge já estabelece separação entre estado neural associativo, payload canônico e leitor; preserva namespaces isolados; aplica autorização antes de resolver conteúdo; registra proveniência; e define restauração fail-closed em incompatibilidades. Esses princípios são reutilizados aqui como base de segurança do AGB. [S1]

O ASM-CM, por sua vez, demonstrou em protocolo controlado um estado retido de aproximadamente **140 KiB por stream**, MQAR de 100% em 32K em três seeds e persistência/restauração após reinicialização de processo. Esses números são evidência de componente, não garantia para um runtime de sistema operacional, e deverão ser revalidados em workloads de segurança. [S2][S3]

---

## 2. Problema

Mecanismos tradicionais de segurança frequentemente avaliam uma operação a partir de identidade, recurso, perfil, capability e regras configuradas. Isso é adequado e deve permanecer como primeira linha de defesa. Porém, determinadas cadeias maliciosas são definidas pela **sequência** de ações.

Exemplo:

```text
navegador baixa arquivo
→ processo lê arquivo
→ cria binário temporário
→ torna binário executável
→ inicia conexão externa
→ lê credencial SSH
→ tenta elevar privilégio
```

Cada evento isoladamente pode ser permitido em algum contexto. A sequência completa pode indicar uma trajetória incompatível com o comportamento autorizado.

A hipótese do AGB é:

> Um estado causal persistente, atualizado por eventos observados do sistema, pode fornecer sinal adicional de segurança para políticas determinísticas sem exigir que o kernel mantenha todo o histórico ativo.

A hipótese é falsificável. AGB só deve ser promovido se demonstrar ganho mensurável sobre baselines de regras, janelas temporais, contadores, correlação convencional e sistemas de detecção existentes.

---

## 3. O que Unix-AGB é — e o que não é

### 3.1 É

- uma camada adicional de segurança stateful para Linux;
- uma arquitetura derivada de Ubuntu para prototipagem e eventual distribuição;
- um runtime que mantém estado por processo, usuário, container, serviço, agente ou tenant;
- um sistema que separa memória associativa de verdade canônica;
- um mecanismo de decisão apoiado por estado histórico e política explícita;
- uma plataforma de pesquisa para segurança de agentes de IA e workloads tradicionais;
- um sistema que pode funcionar inicialmente sem kernel customizado.

### 3.2 Não é

- um kernel novo;
- um substituto para Linux, Ubuntu, AppArmor ou LSM;
- um novo gerenciador de páginas, swap, NUMA ou memória virtual;
- uma rede neural autorizada a decidir arbitrariamente toda syscall;
- um mecanismo que considera o estado neural como fonte canônica de permissões;
- uma promessa de detecção universal de malware;
- um substituto de logs, auditoria, SIEM, EDR, bancos de dados ou event stores;
- uma alegação de que 140 KiB contêm todo o histórico original de forma lossless.

---

## 4. Base tecnológica: por que Ubuntu

O projeto deve reutilizar Ubuntu em vez de construir um sistema do zero.

Ubuntu já fornece:

- kernel Linux;
- drivers e compatibilidade de hardware;
- boot, init e systemd;
- VFS, filesystems e rede;
- gerenciamento de memória virtual;
- namespaces e cgroups;
- empacotamento e atualização;
- AppArmor e recursos de segurança;
- ecossistema de desenvolvimento, observabilidade e administração.

A documentação oficial do Ubuntu descreve AppArmor como uma implementação de Linux Security Module usada para restringir capabilities e permissões de aplicações, e informa que AppArmor é central na política de MAC do Ubuntu. [W3][W4]

O Linux fornece o framework LSM para inserir verificações adicionais de segurança, e também oferece BPF LSM para instrumentar hooks LSM com programas BPF privilegiados, permitindo políticas de MAC e auditoria em runtime. [W1][W2]

A Canonical também documenta a compilação de kernels Ubuntu customizados, portanto um kernel específico do projeto pode ser criado mais tarde se houver uma necessidade que as interfaces existentes não atendam. A própria documentação alerta que o procedimento de build indicado é voltado a desenvolvimento/teste, não automaticamente a produção. [W5]

### 4.1 Decisão arquitetural

**Não criar um SO do zero.**

O produto inicial é:

```text
Ubuntu + AGB Runtime
```

A distribuição própria só aparece depois:

```text
Ubuntu-derived image + AGB Runtime + políticas + tooling
```

E um kernel customizado é a última etapa, não a primeira.

---

## 5. Arquitetura de alto nível

```text
┌──────────────────────────────────────────────────────────────┐
│                         Aplicações                           │
│ browsers · shells · services · containers · AI agents      │
└───────────────────────────┬──────────────────────────────────┘
                            │ syscalls / IPC / network
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                   Linux / Ubuntu Kernel                     │
│ VFS · net · process · namespaces · cgroups · MM             │
│ AppArmor / LSM / BPF hooks                                  │
└───────────────────────────┬──────────────────────────────────┘
                            │ security/audit events
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                      AGB Event Gateway                       │
│ normalize · timestamp · identity · namespace · provenance   │
└──────────────┬───────────────────────────────┬───────────────┘
               │                               │
               ▼                               ▼
┌───────────────────────────┐      ┌───────────────────────────┐
│ ASM-CM Security State     │      │ Canonical Event Store     │
│ bounded causal state      │      │ exact facts + metadata    │
│ per security namespace    │      │ ACL + provenance + hash   │
└──────────────┬────────────┘      └─────────────┬─────────────┘
               │                                  │
               └──────────────┬───────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    AGB Policy Runtime                        │
│ state features + explicit policy + canonical evidence       │
│ policy cache · confidence · abstention · audit              │
└───────────────────────────┬──────────────────────────────────┘
                            │ compiled decision
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                  Deterministic Enforcement                   │
│ AppArmor / BPF-LSM / LSM / cgroups / process isolation     │
│ ALLOW · DENY · AUDIT · LIMIT · QUARANTINE · CHALLENGE      │
└──────────────────────────────────────────────────────────────┘
```

---

## 6. Princípio central: kernel observa e impõe; ASM mantém contexto

O kernel não deve chamar uma rede neural em toda operação sensível.

O desenho deve separar dois ritmos:

### 6.1 Plano rápido — enforcement

Características:

- determinístico;
- bounded latency;
- sem chamadas de rede;
- sem LLM;
- sem dependência de GPU;
- política pré-computada ou cacheada;
- fallback seguro quando o AGB não estiver disponível.

Exemplo:

```text
file_open(/etc/shadow)
→ LSM/AppArmor consulta política efetiva
→ DENY
```

### 6.2 Plano lento — análise stateful

Características:

- recebe eventos assíncronos;
- atualiza ASM-CM;
- correlaciona trajetória;
- consulta payloads autorizados quando necessário;
- recalcula classificação de estado;
- publica uma política efetiva compacta.

Exemplo:

```text
trajectory state changes
→ process:4712 classified elevated-risk
→ publish policy:
   credential.read = deny
   network.outbound = restricted
   child.exec = audit
```

O enforcement continua rápido porque a decisão efetiva já foi materializada.

---

## 7. Componentes

### 7.1 AGB Event Gateway

Responsável por transformar sinais do Linux em contratos estáveis.

Fontes iniciais possíveis:

- tracepoints/BPF;
- audit events;
- process lifecycle;
- file operations relevantes;
- network connect/bind/listen;
- privilege/capability changes;
- mount/namespace changes;
- ptrace;
- exec;
- cgroup/container lifecycle;
- eventos específicos de agent runtimes.

O gateway não deve registrar todo byte de todo evento. Ele deve aplicar filtragem, normalização, rate limiting e políticas de minimização.

### 7.2 Canonical Event Store

A fonte canônica de fatos não é o estado neural.

O store preserva:

- `event_id`;
- timestamp monotônico e wall-clock;
- `subject_id`;
- `namespace_id`;
- operação;
- recurso;
- resultado;
- identidade/credenciais relevantes;
- hashes e metadados;
- policy revision;
- provenance;
- retenção e classificação.

A arquitetura do ASM Memory Bridge já exige essa separação: ASM-CM seleciona associações/IDs; o payload store preserva o conteúdo original, ownership, authorization e provenance. [S1]

### 7.3 ASM-CM Security Runtime

Mantém estado neural compacto por namespace de segurança.

Namespaces candidatos:

```text
host:<machine-id>
user:<uid>
process:<boot-id>:<pid>:<start-time>
service:<systemd-unit>
container:<container-id>
cgroup:<cgroup-id>
agent:<agent-id>
tenant:<tenant-id>
session:<session-id>
```

O runtime deve permitir composição hierárquica sem misturar estados por acidente.

### 7.4 AGB Policy Runtime

Converte estado + evidência + política declarativa em decisão publicável.

Ele não deve aceitar uma saída neural como permissão direta. A decisão final precisa obedecer invariantes explícitas.

Exemplo:

```text
never_allow:
  - untrusted_process reads host_private_key

state_rule:
  if trajectory_risk >= elevated:
      deny network.outbound for unknown_destinations

exception:
  signed_backup_agent may read host_private_key
  only when service identity and attestation match
```

### 7.5 Enforcement Adapter

Backends possíveis:

- AppArmor profile update/reload quando apropriado;
- BPF LSM policies;
- cgroup placement e limites;
- process kill/freeze;
- namespace isolation;
- seccomp profile selection;
- firewall/nftables integration;
- systemd service containment;
- future custom LSM if justified.

O MVP deve escolher poucos mecanismos e medir comportamento antes de aumentar o escopo.

### 7.6 AGB Control Plane

Responsável por:

- configuração;
- policy lifecycle;
- checkpoint allowlist;
- status;
- observabilidade;
- atualização;
- export de evidência;
- rollback;
- administração de namespaces;
- revogação e deletion.

---

## 8. Contratos de dados

### 8.1 SecurityEvent

```json
{
  "event_id": "evt:01J...",
  "occurred_at": "2026-08-15T18:24:00-03:00",
  "monotonic_ns": 48290123711,
  "host_id": "host:7b9...",
  "namespace_id": "process:boot42:4712:99120",
  "subject": {
    "pid": 4712,
    "uid": 1000,
    "gid": 1000,
    "exe": "/usr/bin/python3",
    "service": null,
    "container_id": null,
    "agent_id": null
  },
  "operation": "file.open",
  "resource": {
    "type": "file",
    "path": "/home/user/.ssh/id_ed25519"
  },
  "result": "allowed",
  "policy_revision": "policy:42",
  "labels": ["credential", "sensitive"],
  "provenance": {
    "source": "bpf",
    "hook": "file_open"
  }
}
```

### 8.2 SecurityStateSummary

```json
{
  "namespace_id": "process:boot42:4712:99120",
  "state_revision": 192,
  "risk_band": "elevated",
  "confidence": 0.87,
  "signals": [
    "download_to_exec_chain",
    "new_external_destination",
    "credential_access_after_exec"
  ],
  "checkpoint_fingerprint": "sha256:...",
  "updated_at": "2026-08-15T18:24:02-03:00"
}
```

### 8.3 PolicyDecision

```json
{
  "decision_id": "dec:01J...",
  "namespace_id": "process:boot42:4712:99120",
  "policy_revision": "policy:42",
  "state_revision": 192,
  "effect": "deny",
  "scope": "credential.read",
  "reason_codes": [
    "BASE_POLICY_SENSITIVE_CREDENTIAL",
    "STATE_ELEVATED"
  ],
  "expires_at": "2026-08-15T18:29:02-03:00",
  "evidence_ids": ["evt:01J...", "evt:01K..."],
  "fail_closed": true
}
```

### 8.4 EnforcementRecord

```json
{
  "decision_id": "dec:01J...",
  "kernel_event_id": "k:991882",
  "backend": "bpf-lsm",
  "effect_applied": "deny",
  "latency_us": 31,
  "policy_revision": "policy:42"
}
```

---

## 9. Modelo de estado e namespaces

### 9.1 Isolamento

O ASM Memory Bridge exige um estado por namespace e determina que estados não sejam usados entre namespaces sem política explícita de compartilhamento. [S1]

Unix-AGB reutiliza esse princípio para segurança.

Regra básica:

```text
process A state != process B state
user A state    != user B state
agent A state   != agent B state
tenant A state  != tenant B state
```

Compartilhamento deve ser explícito e rastreável.

### 9.2 Hierarquia

Um evento pode atualizar mais de um nível, desde que cada atualização seja separada:

```text
process state
   ↓ derived signal
user state
   ↓ derived signal
host state
```

O payload original não deve ser replicado sem necessidade.

### 9.3 Identidade de processo

PID sozinho não é identidade suficiente por causa de reutilização. Usar composição com boot ID e start time ou outro identificador estável equivalente.

### 9.4 Persistência

Snapshots devem incluir:

- fingerprint do checkpoint ASM-CM;
- schema version;
- configuration fingerprint;
- state tensors;
- last committed event sequence;
- event-store revision;
- checksum.

A regra do Memory Bridge é adequada: restauração deve falhar de forma fechada quando checkpoint, schema ou store revision forem incompatíveis. [S1]

---

## 10. Segurança de memória: distinção essencial

"Controle de memória" pode significar duas coisas diferentes.

### 10.1 Memory management do kernel

Inclui:

- page allocation;
- page fault;
- swap;
- reclaim;
- NUMA;
- virtual memory mappings;
- OOM handling.

**Não é o alvo inicial do AGB.**

Colocar inferência neural em page-fault ou allocator hot paths criaria risco de latência, deadlock, reentrância e indisponibilidade.

### 10.2 Information-flow / security memory

É o alvo mais promissor:

- que processo viu qual recurso;
- qual cadeia levou ao acesso;
- quem originou o dado;
- para onde o dado foi enviado;
- qual agente recebeu determinada evidência;
- qual autorização estava vigente;
- quais associações históricas são relevantes agora.

Assim, o AGB funciona como **memória causal de segurança**, não como substituto do Linux MM.

---

## 11. Política e invariantes

A arquitetura precisa de três níveis.

### 11.1 Política estática não-negociável

Exemplos:

- um namespace sem autorização nunca lê payload de outro tenant;
- checkpoints não allowlisted não são carregados;
- estado corrompido não pode ampliar privilégio;
- falha do daemon não converte DENY em ALLOW para recursos classificados como fail-closed;
- uma saída ASM nunca pode conceder capability que a política base proíbe.

### 11.2 Política dinâmica stateful

Pode restringir privilégios com base na trajetória.

Exemplos:

```text
normal → monitor
monitor → elevated
elevated → restricted
restricted → quarantined
```

### 11.3 Política de recuperação de evidência

Antes de resolver um evento/payload, verificar:

- requester;
- namespace;
- classification;
- purpose;
- reader destination;
- retention;
- time scope.

Esse desenho vem diretamente do princípio de least-context disclosure do ASM Memory Bridge. [S1]

---

## 12. Estados de decisão

Não limitar o sistema a ALLOW/DENY.

```text
ALLOW       operação normal
DENY        bloquear
AUDIT       permitir e registrar com prioridade
LIMIT       reduzir quota/capability/rate
CHALLENGE   exigir confirmação/autenticação adicional
FREEZE      suspender processo/cgroup
QUARANTINE  mover para domínio restrito
KILL        encerrar quando política explícita autorizar
ABSTAIN     AGB sem suporte suficiente; usar política base
```

**ABSTAIN é importante.** Se o estado não fornece evidência suficiente, o sistema não deve inventar justificativa.

---

## 13. Caminho de decisão

### 13.1 Evento assíncrono

```text
kernel event
→ gateway
→ canonical append
→ ASM-CM write
→ state revision
→ policy evaluation
→ compiled policy/cache
→ enforcement backend
```

### 13.2 Evento sensível síncrono

```text
security hook
→ deterministic base policy
→ cached AGB restriction
→ decision
```

Nenhum LLM aparece no caminho.

### 13.3 Investigação humana/agentic

Um LLM pode ser usado fora do hot path para explicar evidência:

```text
admin asks "why was process 4712 quarantined?"
→ authorized evidence package
→ local/remote reader
→ explanation with evidence IDs
```

A explicação não altera retroativamente a decisão canônica.

---

## 14. Uso para agentes de IA

Esse é um dos casos mais fortes da arquitetura.

Cada agente recebe identidade explícita:

```text
agent:finance
agent:developer
agent:email
agent:research
```

E capabilities distintas:

```text
agent:finance
  read: invoices
  write: reports
  network: finance APIs
  deny: source-code repositories

agent:developer
  read/write: repositories
  execute: build sandbox
  deny: production secrets by default
```

O estado histórico do agente pode complementar a política:

```text
agent requests production secret
→ base permission check
→ recent trajectory check
→ provenance of request
→ tool-chain state
→ compiled decision
```

### 14.1 Benefício principal

O agente não recebe o histórico completo nem credenciais indiscriminadamente. O AGB pode autorizar somente a evidência necessária para a próxima ação.

### 14.2 Relação com Aletheion grounding

O padrão arquitetural é consistente com a separação já usada pelo Memory Bridge: recuperação, autorização, evidência mínima e leitor independente. [S1]

---

## 15. Threat model

### 15.1 Adversários considerados

- processo user-space comprometido;
- malware executando como usuário comum;
- container comprometido;
- agente de IA induzido por prompt injection;
- ferramenta chamada por agente com intenção incompatível;
- usuário tentando atravessar namespace/tenant;
- processo tentando contaminar o estado do AGB;
- replay de eventos;
- adulteração do event store;
- checkpoint ASM não autorizado;
- tentativa de exfiltração por reader remoto.

### 15.2 Fora do escopo inicial

- atacante com controle total do kernel;
- firmware/hardware comprometido;
- hipervisor hostil;
- side channels de hardware;
- proteção contra todas as classes de rootkit;
- prova formal completa de não interferência.

### 15.3 Regra de confiança

```text
Kernel-enforced identity > canonical event store > explicit policy > ASM state > LLM explanation
```

O estado neural nunca deve superar a autoridade das camadas anteriores.

---

## 16. Falhas e respostas

| Falha | Resposta exigida |
|---|---|
| daemon AGB indisponível | enforcement base permanece; regras críticas usam fallback definido |
| snapshot incompatível | fail closed / reinitialize sem ampliar privilégio |
| payload ausente | não alegar evidência; abstain |
| cross-namespace retrieval | incidente crítico |
| estado cresce com histórico | regressão de compactness |
| latência excede orçamento | degradar para policy cache/base policy |
| checkpoint desconhecido | recusar carga |
| event sequence gap | marcar state untrusted até resync |
| reader remoto indisponível | nenhuma alteração no enforcement |
| ASM classifica errado | política explícita limita efeito e auditoria permite reversão |

---

## 17. Desempenho e latência

O projeto deve medir separadamente:

- custo de coleta;
- custo de append canônico;
- custo ASM-CM por evento;
- latência de recomputação de policy state;
- latência do enforcement cache;
- RAM/VRAM do runtime;
- bytes de estado por namespace;
- storage por evento;
- custo incremental por 1, 10, 100, 1.000 e 10.000 entidades.

O benchmark de memória persistente do projeto já adota essa separação e destaca que retained neural state, snapshot, runtime RSS, VRAM, write/query latency e reader context devem ser reportados separadamente. [S3]

### 17.1 Não usar 140 KiB como promessa de produto

O valor de ~140 KiB foi observado em configuração específica do ASM-CM. A documentação de benchmark do próprio projeto determina que esse valor deve ser tratado como resultado anterior e revalidado em cada configuração. [S3]

---

## 18. Modelo de implantação

### 18.1 Unix-AGB v0 — observabilidade

```text
Ubuntu stock kernel
+ AGB daemon
+ BPF collectors
+ canonical event store
+ ASM-CM state
+ dashboard
```

Sem bloqueio automático.

Objetivo: medir qualidade do estado e falsas detecções.

### 18.2 Unix-AGB v1 — enforcement assistido

Adicionar:

- policy cache;
- AppArmor integration;
- BPF-LSM para poucos hooks;
- cgroup isolation;
- rollback.

Objetivo: bloquear somente classes claramente definidas.

### 18.3 Unix-AGB v2 — Agent Security Runtime

Adicionar:

- agent identities;
- tool capability broker;
- per-agent ASM state;
- evidence authorization;
- network/resource boundaries;
- prompt-injection trajectory tests.

### 18.4 Unix-AGB v3 — Developer Preview

Criar imagem Ubuntu derivada com:

- pacotes AGB pré-instalados;
- políticas default;
- systemd units;
- diagnostics;
- signed artifacts;
- recovery mode;
- installer/image pipeline.

### 18.5 Unix-AGB v4 — kernel customizado opcional

Somente se métricas mostrarem necessidade real de:

- hook ausente;
- informação insuficiente;
- latência impossível via mecanismo existente;
- proteção que exija integração mais profunda.

A Canonical documenta como compilar kernels Ubuntu customizados; isso permite manter o ecossistema Ubuntu em vez de criar um kernel próprio. [W5]

---

## 19. Pacotes propostos

```text
agb-runtime
agb-event-gateway
agb-policy-engine
agb-asm-runtime
agb-store
agb-bpf
agb-apparmor
agb-agent-broker
agb-cli
agb-dashboard
agb-devtools
```

Layout inicial:

```text
/etc/agb/
  agb.yaml
  policies/
  checkpoints.allowlist
  readers/

/usr/bin/
  agbctl
  agb-runtime

/usr/lib/agb/
  bpf/
  policy/
  runtime/

/var/lib/agb/
  states/
  snapshots/
  store/
  policy-cache/

/var/log/agb/
  audit/
```

Conteúdo sensível deve ser minimizado e, em produção, criptografado de acordo com o threat model.

---

## 20. Serviços systemd

Proposta:

```text
agb-event-gateway.service
agb-runtime.service
agb-policy.service
agb-enforcer.service
agb-dashboard.service (opcional)
```

Dependências devem evitar ciclos de boot. O host deve conseguir iniciar com política base mesmo se o componente neural falhar.

---

## 21. API local

Preferência inicial: Unix domain sockets com autenticação por credencial de processo.

### 21.1 Estado

```text
GET /v1/namespaces/{id}/state
```

### 21.2 Evidência

```text
POST /v1/evidence/query
```

### 21.3 Política

```text
GET /v1/namespaces/{id}/effective-policy
POST /v1/policies/validate
POST /v1/policies/apply
```

### 21.4 Auditoria

```text
GET /v1/decisions/{decision_id}
```

### 21.5 Administração

```text
POST /v1/runtime/snapshot
POST /v1/runtime/restore
GET  /v1/runtime/health
```

APIs remotas devem ser opcionais e explicitamente autenticadas.

---

## 22. CLI

```bash
agbctl status
agbctl namespaces list
agbctl state show process:...
agbctl decisions tail
agbctl evidence explain <decision-id>
agbctl policy validate ./policy.yaml
agbctl policy apply ./policy.yaml
agbctl quarantine <namespace-id>
agbctl release <namespace-id>
agbctl snapshot
agbctl doctor
```

---

## 23. Observabilidade

Métricas mínimas:

```text
agb_events_total
agb_events_dropped_total
agb_event_ingest_latency_seconds
agb_state_update_latency_seconds
agb_state_bytes
agb_snapshot_bytes
agb_policy_compile_latency_seconds
agb_policy_cache_hits_total
agb_policy_cache_misses_total
agb_enforcement_latency_seconds
agb_denies_total
agb_quarantines_total
agb_abstentions_total
agb_cross_namespace_violation_total
agb_state_restore_failures_total
```

### 23.1 Trace de decisão

```text
kernel event
→ normalized event ID
→ state revision
→ evidence IDs
→ policy revision
→ compiled effect
→ enforcement backend
→ applied result
```

A auditoria deve ser possível sem expor payload privado indiscriminadamente.

---

## 24. Segurança do próprio AGB

O AGB vira infraestrutura privilegiada e, portanto, precisa ser mais protegido do que aplicações comuns.

Requisitos:

- execução com mínimo privilégio possível;
- separar collector, model runtime e enforcer em processos distintos;
- filesystem permissions estritas;
- signed checkpoints;
- allowlist de configuração;
- defesa contra symlink/path traversal;
- atomic snapshots;
- monotonic sequence numbers;
- checksums;
- rate limits;
- bounded queues;
- watchdog;
- logs sem segredos;
- zero trust em payload user-space;
- fuzzing de contratos externos;
- testes de crash/restart;
- rollback de policy;
- recovery boot sem ASM.

### 24.1 BPF

BPF LSM é poderoso e privilegiado. O projeto deve limitar programas carregados, validar versões, assinar artefatos quando possível e evitar uma superfície de configuração arbitrária em produção. A documentação oficial do kernel descreve BPF LSM como mecanismo capaz de implementar MAC e auditoria em hooks LSM. [W1]

---

## 25. Interação com AppArmor

AppArmor deve continuar sendo uma política base, não ser removido no primeiro protótipo. A documentação do Ubuntu o descreve como implementação LSM para restringir capabilities e permissões e como tecnologia central no Ubuntu. [W3][W4]

Estratégia recomendada:

```text
AppArmor = política estrutural estável
AGB      = restrição stateful adicional
```

AGB não deve ampliar privilégios concedidos pelo perfil base; no MVP, deve apenas manter, auditar ou restringir.

---

## 26. Relação com LSM e BPF-LSM

O framework LSM existe para permitir verificações adicionais de segurança no kernel. [W2]

BPF-LSM permite instrumentar hooks LSM por programas BPF privilegiados. [W1]

Uso proposto:

- começar com hooks mínimos;
- manter decisão em mapas/cache simples;
- não executar lógica neural dentro de BPF;
- limitar estado por chave;
- versionar policy maps;
- suportar rollback atômico.

Exemplo conceitual:

```text
key: process_identity + operation_class
value: allow/deny/audit + expiry + policy_revision
```

---

## 27. Testes de segurança

### 27.1 Unitários

- contratos rejeitam campos inválidos;
- namespaces não se misturam;
- PID reuse não reutiliza estado;
- policy cache expira corretamente;
- snapshot verifica fingerprint;
- corrupted snapshot falha fechado;
- missing payload causa abstention;
- allowlist de checkpoint funciona.

### 27.2 Integração

- exec → file → network chains;
- privilege escalation attempts;
- cross-container access;
- agent tool abuse;
- restart durante atividade;
- event backlog;
- BPF reload;
- AppArmor policy reload;
- policy rollback.

### 27.3 Adversariais

- event flooding;
- state poisoning;
- namespace spoofing;
- time manipulation;
- replay;
- payload injection;
- prompt injection contra reader de explicação;
- attempts to make explanation alter enforcement;
- malformed BPF event data;
- compromised agent attempting capability confusion.

---

## 28. Benchmark científico

O experimento precisa comparar AGB com baselines reais.

### 28.1 Baselines

1. política Linux/AppArmor sem AGB;
2. regras de sequência determinísticas;
3. sliding-window event correlator;
4. contadores/risk score convencional;
5. ASM-CM state sem payload retrieval;
6. ASM-CM + canonical evidence;
7. opcionalmente EDR/SIEM equivalente quando metodologia permitir.

### 28.2 Métricas

- detection recall;
- precision;
- false positives por hora;
- time-to-detect;
- time-to-enforce;
- CPU overhead;
- memory overhead;
- bytes state/entity;
- storage/event;
- boot overhead;
- p50/p95/p99 event latency;
- p50/p95/p99 enforcement latency;
- restart recovery;
- cross-namespace violation rate;
- explainability/evidence completeness;
- operator reversal rate.

### 28.3 Gate de promoção

AGB não deve bloquear automaticamente workloads amplos até demonstrar:

- false-positive rate aceitável;
- recuperação confiável após restart;
- bounded resource usage;
- zero cross-namespace leakage observado nos testes;
- fallback seguro;
- evidência reproduzível de ganho sobre baselines.

---

## 29. Primeiro experimento recomendado

### 29.1 Objetivo

Demonstrar que trajetória agrega sinal além do evento isolado.

### 29.2 Workload

Criar 20 sequências benignas e 20 sequências maliciosas controladas, contendo operações semelhantes em ordens/contextos diferentes.

Exemplo:

```text
Benigno:
IDE → compiler → build artifact → localhost test

Malicioso:
downloaded document → script → executable temp → external host → credential read
```

### 29.3 Modos

```text
A: regras isoladas
B: regras com janela temporal
C: ASM-CM trajectory state
D: ASM-CM + evidence retrieval + explicit policy
```

### 29.4 Resultado mínimo

O primeiro paper/protocolo deve responder:

> O estado causal melhora precisão/recall de classificação de cadeias sem criar overhead ou falsos positivos inaceitáveis?

Não começar afirmando que o sistema é mais seguro; medir.

---

## 30. Roadmap de engenharia

### Milestone 0 — Skeleton

- repositório;
- contratos;
- event store;
- fake ASM runtime;
- fake enforcer;
- tests.

### Milestone 1 — Ubuntu observer

- BPF collectors;
- process identity;
- file/exec/network subset;
- event normalization;
- CLI tail;
- no enforcement.

### Milestone 2 — ASM-CM integration

- per-namespace state;
- snapshot/restore;
- state size accounting;
- event-to-state pipeline;
- deterministic fingerprints.

### Milestone 3 — Policy engine

- static invariants;
- state bands;
- evidence query;
- cache;
- dry-run decisions.

### Milestone 4 — Enforcement pilot

- small BPF-LSM/AppArmor integration;
- deny one controlled class;
- rollback;
- fail-safe tests.

### Milestone 5 — Agent broker

- agent identities;
- capabilities;
- tool proxy;
- per-agent state;
- prompt-injection scenarios.

### Milestone 6 — Developer Preview

- packages;
- installer;
- Ubuntu image;
- signed release;
- documentation;
- benchmark report.

### Milestone 7 — Kernel decision

Review formal:

```text
Do existing hooks provide enough information and latency?
YES → stay on stock Ubuntu kernel.
NO  → document missing capability and prototype a minimal patch.
```

---

## 31. Estrutura de repositório proposta

```text
unix-agb/
├── README.md
├── ARCHITECTURE.md
├── THREAT_MODEL.md
├── SECURITY.md
├── BENCHMARK.md
├── ROADMAP.md
├── LICENSES.md
├── docs/
│   ├── contracts.md
│   ├── policy-model.md
│   ├── namespaces.md
│   ├── event-model.md
│   ├── persistence.md
│   ├── ubuntu-integration.md
│   ├── bpf-lsm.md
│   ├── apparmor.md
│   ├── agent-security.md
│   └── recovery.md
├── src/
│   └── agb/
│       ├── gateway/
│       ├── runtime/
│       ├── state/
│       ├── store/
│       ├── policy/
│       ├── enforcement/
│       ├── agents/
│       ├── api/
│       └── observability/
├── bpf/
│   ├── events/
│   └── lsm/
├── policies/
│   ├── base/
│   ├── agents/
│   └── examples/
├── packaging/
│   ├── debian/
│   ├── systemd/
│   └── image/
├── benchmarks/
│   ├── workloads/
│   ├── baselines/
│   └── scoring/
└── tests/
    ├── unit/
    ├── integration/
    ├── adversarial/
    └── recovery/
```

---

## 32. Naming

### 32.1 AGB

Nome recomendado para a tecnologia:

> **Aletheion Guard Bridge (AGB)**

O nome comunica continuidade com o ASM Memory Bridge e descreve a função de ponte entre estado, evidência, política e enforcement.

### 32.2 Unix-AGB

Como **nome de trabalho interno**, Unix-AGB é claro e forte. Porém, antes de uso comercial, é recomendável revisão de marca.

A Open Group informa que **UNIX® é marca registrada** e que somente sistemas conformes e certificados segundo a Single UNIX Specification se qualificam para usar a marca UNIX em conexão com o produto. [W6][W7]

Portanto, para produto público antes de certificação/licenciamento, alternativas mais seguras conceitualmente seriam:

- **AGB Linux**;
- **Aletheion Guard OS**;
- **Aletheion Secure Linux**;
- **AGB Runtime for Ubuntu**;
- **Aletheion Guard Runtime**.

Esta observação não substitui aconselhamento jurídico de marca.

---

## 33. Licenciamento e dependências

O projeto deve documentar separadamente:

- licença do código AGB;
- licença do ASM-CM;
- licença do ASM Memory Bridge;
- licenças de dependências;
- termos de distribuição Ubuntu;
- artefatos de kernel/BPF;
- modelos/checkpoints;
- assets e tooling.

O código ASM público do programa já utiliza AGPL-3.0-only com via comercial documentada nos materiais do projeto; qualquer integração do AGB deve verificar compatibilidade de distribuição e obrigações antes de release. [S4]

---

## 34. Requisitos de privacidade

- minimizar eventos persistidos;
- classificar payloads por sensibilidade;
- authorization-before-resolution;
- reader remoto recebe somente evidência explicitamente autorizada;
- suporte a modo local-only;
- deletion por namespace;
- política de retenção;
- auditoria de disclosure;
- redaction de secrets em logs;
- separar métricas de conteúdo.

O Memory Bridge já define que autorização deve ser aplicada antes de payload resolution e antes de o reader receber evidência. [S1]

---

## 35. Recovery e operação degradada

O sistema deve continuar seguro quando o componente ASM falhar.

### 35.1 Modos

```text
NORMAL
DEGRADED_STATE
BASE_POLICY_ONLY
RECOVERY
MAINTENANCE
```

### 35.2 Regra

Falha neural nunca deve resultar automaticamente em ampliação de privilégio.

### 35.3 Boot

A máquina deve ser capaz de iniciar com:

```text
Linux + AppArmor/base policy
```

mesmo se:

```text
ASM checkpoint unavailable
AGB state corrupted
GPU unavailable
model runtime failed
```

---

## 36. Critérios para kernel customizado

Somente considerar patch de kernel quando pelo menos um destes critérios for atendido e documentado:

1. hook necessário inexistente;
2. informação necessária não pode ser obtida com segurança por interfaces existentes;
3. enforcement precisa ocorrer antes de qualquer ponto acessível a AppArmor/LSM/BPF;
4. overhead do caminho existente viola requisito medido;
5. uma propriedade de segurança não pode ser garantida sem alteração mínima do kernel.

Se necessário:

```text
Ubuntu kernel source
+ minimal AGB patchset
+ reproducible config
+ package/image build
+ regression suite
```

Evitar fork permanente sem necessidade.

---

## 37. Critérios de sucesso do projeto

### Técnico

- zero cross-namespace leakage observado;
- state restore determinístico;
- bounded state em workloads escolhidos;
- enforcement latency dentro do orçamento;
- fallback seguro;
- rollback confiável;
- ausência de LLM no hot path;
- event provenance completa para decisões críticas.

### Científico

- benchmark pareado;
- baselines fortes;
- false positives publicados;
- overhead publicado;
- ablações do ASM;
- resultados reproduzíveis;
- falhas documentadas.

### Produto

- instalação simples em Ubuntu;
- `agbctl doctor` diagnostica ambiente;
- políticas compreensíveis;
- logs auditáveis;
- proteção específica para agentes demonstrável;
- atualização segura.

---

## 38. Questões de pesquisa abertas

1. Qual granularidade de evento produz melhor relação sinal/custo?
2. Estado por processo é suficiente ou estado hierárquico melhora detecção?
3. Como evitar state poisoning por evento adversarial?
4. Quanto tempo uma associação de segurança deve persistir?
5. O ASM-CM preserva sinais úteis sob milhões de eventos de SO?
6. Como comparar trajetória neural com HMM, RNN, SSM e correlação convencional?
7. Qual o menor policy cache necessário para hot-path enforcement?
8. Como provar isolamento entre tenants além de testes empíricos?
9. Quais capacidades de agentes se beneficiam de memória causal sem aumentar risco?
10. Em que ponto um custom LSM é justificável?

---

## 39. Conclusão arquitetural

A proposta mais defensável para Unix-AGB não é construir um sistema operacional novo. É construir **uma camada de segurança stateful sobre Ubuntu**, usando mecanismos Linux existentes para coleta e enforcement e ASM-CM para manter contexto causal compacto.

A divisão de responsabilidades é:

```text
Linux/Ubuntu
    = hardware, processos, memória virtual, rede, filesystem, enforcement primitives

AppArmor / LSM / BPF
    = hooks, policy enforcement, audit

AGB
    = orchestration, policy state, security control plane

ASM-CM
    = bounded causal/associative state

Canonical Event Store
    = exact historical truth and provenance

ASM Memory Bridge principles
    = namespace isolation, authorization, evidence resolution, fail-closed restore

LLM (optional)
    = human-readable explanation only; never authority in hot path
```

O primeiro protótipo pode rodar em um Ubuntu comum sem modificar o kernel. Se os experimentos demonstrarem que a memória causal realmente adiciona valor, o projeto pode avançar para enforcement, proteção de agentes, imagem Ubuntu derivada e, apenas por último, um kernel customizado.

A frase de posicionamento técnico sugerida é:

> **Aletheion Guard Bridge is a stateful security runtime for Linux that turns system behavior into persistent causal state, resolves only authorized evidence, and compiles that state into deterministic enforcement policies.**

---

# Referências

## Fontes internas do projeto

**[S1]** *ASM Memory Bridge — Architecture*, 6 ago. 2026. Define separação ASM-CM / payload store / reader, namespaces, autorização antes de payload resolution, snapshots, proveniência e fail-closed restore.  
**[S2]** *AletheionAGI ASM-CM Pitch Deck 2026*. Resultados controlados: MQAR 32K, estado aproximado de 140 KiB por stream, endurance e limites declarados.  
**[S3]** *Persistent Memory Scaling Benchmark*. Define contabilidade separada de retained state, snapshots, RAM, VRAM, storage e custo incremental por agente, e determina revalidar o valor de ~140 KiB em cada configuração.  
**[S4]** *FAQ técnico e metodologia de benchmark / documentação ASM*. Descreve licença AGPL-3.0-only do projeto público e licenciamento comercial separado.

## Fontes oficiais externas

**[W1]** Linux Kernel Documentation — *LSM BPF Programs*. BPF programs podem instrumentar hooks LSM para políticas MAC e audit.  
https://docs.kernel.org/bpf/prog_lsm.html

**[W2]** Linux Kernel Documentation — *Linux Security Module Usage*. O framework LSM fornece mecanismo para hooks adicionais de verificações de segurança.  
https://docs.kernel.org/admin-guide/LSM/index.html

**[W3]** Ubuntu Security Documentation — *AppArmor*. AppArmor restringe capabilities e permissões de aplicações e integra o modelo LSM.  
https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/

**[W4]** Ubuntu Security Documentation — *Privilege restriction*. Ubuntu utiliza AppArmor como MAC por padrão e documenta outros mecanismos baseados em LSM.  
https://documentation.ubuntu.com/security/security-features/privilege-restriction/

**[W5]** Ubuntu Kernel Documentation — *How to build an Ubuntu Linux kernel*. Processo oficial para customização e compilação de kernel Ubuntu para desenvolvimento/teste.  
https://documentation.ubuntu.com/kernel/how-to/develop-customise/build-kernel/

**[W6]** The Open Group — *UNIX® Certification Program*. Somente sistemas plenamente conformes e certificados segundo a Single UNIX Specification se qualificam para usar a marca UNIX®.  
https://www.opengroup.org/certifications/unix

**[W7]** The Open Group — *Trademarks*. UNIX® é marca registrada da The Open Group.  
https://www.opengroup.org/trademarks

---

## Nota de maturidade

Este documento descreve uma **arquitetura proposta**, não um sistema já implementado ou validado. As afirmações sobre ASM-CM são limitadas aos protocolos internos citados. As integrações Linux descritas são caminhos arquiteturais possíveis apoiados por interfaces oficiais, mas o desempenho, segurança e compatibilidade do AGB precisam ser demonstrados por implementação e benchmark próprios.
