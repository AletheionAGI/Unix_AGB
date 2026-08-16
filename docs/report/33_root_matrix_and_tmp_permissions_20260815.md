# Etapa 33 — execução root e permissões temporárias

Corrigidos dois problemas encontrados no laboratório:

- o diretório temporário era criado com modo `0700`, impedindo `runuser` de
  atravessar o caminho até o binário;
- quando a matriz é executada como root, o UID virtual 0 do user namespace
  coincide com a allowlist `0`, portanto a decisão correta é `admin-ok`, não
  rejeição.

O harness agora torna apenas seu diretório temporário executável (`0755`) e a
matriz ajusta a expectativa do namespace conforme a identidade do processo.

Próximo passo: repetir o comando privilegiado e confirmar `status: passed` e a
presença do audit log.
