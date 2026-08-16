# Etapa 65 — rotação de revisão de autorização

O executor agora inicia cada variante em `lab-authz-v1` e reinicia o admin
server em `lab-authz-v2`. Ele exige que os quatro eventos sejam marcados,
na ordem, como `v1`, `v1`, `v2`, `v2`.

Próximo passo: executar a matriz privilegiada e confirmar a fronteira de
revisão preservada no audit log.
