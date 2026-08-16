# Etapa 35 — requisição dedicada e audit log

O harness agora aguarda o socket do servidor iniciado com `runuser`, envia uma
requisição `list` autenticada pelo token de laboratório e valida a resposta
`admin-ok` antes de exigir a criação do audit log.

Isso corrige o falso negativo anterior: iniciar o servidor sozinho não gera
necessariamente uma entrada de auditoria.

Próximo passo: repetir o comando privilegiado e inspecionar o registro JSONL
produzido pela operação dedicada.
