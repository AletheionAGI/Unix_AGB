# Etapa 52 — validação dupla após restart

O executor agora reenviará tanto a conta allowlisted quanto a conta outsider
após cada reinicialização. Cada variante exigirá quatro eventos de auditoria:
as duas decisões antes e as duas depois do restart.

Assim, o teste confirma preservação de aceitação e de rejeição, não apenas da
aceitação da conta allowlisted.

Próximo passo: executar a matriz privilegiada e verificar que as decisões após
restart reproduzem as decisões iniciais.
