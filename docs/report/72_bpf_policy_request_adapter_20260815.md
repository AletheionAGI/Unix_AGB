# Etapa 72 — adaptador BPF para policy broker

O observer agora transforma cada evento canônico em `PolicyBrokerRequest`, com
namespace, recurso, revisão, efeito solicitado e operação. O evento original
permanece emitido junto da requisição e da resposta para preservar proveniência.

Próximo passo: executar o pipeline BPF privilegiado e confirmar decisões sem
`invalid request`.
