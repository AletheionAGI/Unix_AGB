# Etapa 34 — gravação do audit log pela conta dedicada

O teste privilegiado já passava a matriz, mas o servidor não conseguia criar o
audit log porque o diretório temporário permanecia pertencendo a root.

O harness agora aplica `chown` do diretório temporário para o UID/GID da conta
dedicada antes de iniciar `runuser` e falha explicitamente se o audit log não
for criado.

Próximo passo: repetir o comando privilegiado e inspecionar o conteúdo do
audit log gerado durante a execução.
