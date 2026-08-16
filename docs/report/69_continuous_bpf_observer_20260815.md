# Etapa 69 — observer BPF contínuo

Adicionado `make live-bpf-observer`, que executa o programa `bpftrace`,
normaliza cada linha em streaming com `bpf_to_events.py` e emite uma contagem
final de eventos. O runner informa explicitamente quando `bpftrace` não está
instalado.

Próximo passo: rodar com privilégios BPF no host e conectar o fluxo normalizado
diretamente ao socket do policy broker.
