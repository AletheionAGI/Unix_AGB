# Contrato de enforcement `connect`

O recurso de rede canônico contém `family`, `protocol`, `address` e `port`.
Leituras de `sockaddr` são limitadas a 128 bytes. Famílias desconhecidas,
comprimento inválido ou falha de leitura são erros fail-closed.

As famílias inicialmente permitidas são `AF_INET`, `AF_INET6` e `AF_UNIX`.
O caminho Unix é limitado a 108 bytes e não é resolvido por symlink.

The observer records `family`, numeric and normalized protocol, socket type,
destination address and port for IPv4/IPv6, or the bounded Unix-socket path.
Sockets created before observer attachment may have unknown protocol metadata;
the destination remains authoritative when the kernel exposes its `sockaddr`.
An unresolved file descriptor is incomplete evidence and must not be treated as
proof of external transmission.
