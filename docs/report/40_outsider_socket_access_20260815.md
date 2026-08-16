# Etapa 40 — conexão do outsider ao socket

O teste outsider falhava antes da decisão de autorização porque o socket Unix
temporário herdava modo restrito e rejeitava a conexão no filesystem.

O harness agora aplica modo `0666` somente ao socket temporário após sua criação.
A segurança efetiva permanece em `SO_PEERCRED` e na allowlist UID/GID, portanto
a conta outsider consegue chegar ao broker e recebe `peer-not-allowlisted`.

Próximo passo: repetir o harness e confirmar as decisões accepted/rejected.
