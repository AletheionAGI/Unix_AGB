# Etapa 59 — recuperação da janela de rate limit

Adicionado `AGB_ADMIN_RATE_WINDOW_SECS`, com padrão de 60 segundos. O teste de
laboratório usa uma janela de um segundo: esgota cinco requisições, confirma a
sexta como `rate-limit`, aguarda a expiração e confirma uma nova `admin-ok`.

Próximo passo: remover o campo `operator` controlado pelo cliente da requisição
administrativa, pois a identidade autoritativa já vem de `SO_PEERCRED`.
