# Etapa 61 — spoofing de operador

Adicionado `make admin-operator-spoofing`. O cliente envia um campo
`operator` falsificado (`pid:1:uid:0:gid:0`); o teste exige que resposta e
audit log não o reproduzam e contenham o UID real observado via `SO_PEERCRED`.

Próximo passo: registrar também a versão de configuração de autorização em
cada evento administrativo.
