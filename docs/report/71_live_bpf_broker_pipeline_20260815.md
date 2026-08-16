# Etapa 71 — pipeline BPF e broker ao vivo

Adicionado `make live-bpf-broker-pipeline`. O alvo cria um socket temporário,
inicia o broker persistente, executa o observer por dez segundos conectado ao
socket e encerra o broker ao final.

Próximo passo: executar o alvo sob privilégio BPF e gerar atividade de processo
para validar eventos e respostas end-to-end.
