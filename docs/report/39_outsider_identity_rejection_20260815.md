# Etapa 39 — conta fora da allowlist

O harness privilegiado agora cria duas contas temporárias: a conta dedicada,
incluída na allowlist, e uma conta outsider, não incluída. Ambas enviam uma
operação autenticada ao mesmo socket.

Critérios:

- conta dedicada: `admin-ok`;
- conta outsider: `peer-not-allowlisted`;
- contas removidas ao finalizar.

Próximo passo: repetir o comando privilegiado e registrar as duas decisões no
audit log.
