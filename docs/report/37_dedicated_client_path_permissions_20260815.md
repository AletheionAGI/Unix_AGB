# Etapa 37 — caminho do cliente dedicado

Corrigida a última falha de permissão: `admin_request.py` também era carregado
por um caminho privado dentro do workspace, inacessível à conta temporária.

O harness agora copia o cliente para o diretório temporário, ajusta a posse
para o UID/GID dedicado e executa a requisição a partir desse local.

Próximo passo: repetir o comando privilegiado e validar a resposta `admin-ok`
com o audit log criado.
