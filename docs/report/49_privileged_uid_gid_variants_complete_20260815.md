# Etapa 49 — variantes privilegiadas UID/GID concluídas

Execução no host de laboratório confirmou os seis casos com duas contas reais
compartilhando GID `971`:

| Regra | Conta allowlisted | Conta distinta no mesmo grupo |
|---|---|---|
| UID + GID | `admin-ok` | `peer-not-allowlisted` |
| Somente GID | `admin-ok` | `admin-ok` |
| Somente UID | `admin-ok` | `peer-not-allowlisted` |

Isso confirma que a allowlist aplica a semântica esperada: uma regra de grupo
aceita membros desse grupo; uma regra de UID identifica apenas a conta
específica; e regras de UID e GID em conjunto exigem os dois atributos.

Próximo passo: persistir também os audit logs da matriz de variantes e testar
reinicialização do admin server sem perder a configuração de autorização.
