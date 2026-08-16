# Etapa 70 — fluxo BPF para policy broker

O runner BPF aceita `--broker-socket`. Quando configurado, cada evento
normalizado é enviado como JSONL ao broker e a resposta correspondente é
emitida junto ao evento.

Próximo passo: iniciar o broker persistente e exercitar esse pipeline em um
host com eventos BPF reais.
