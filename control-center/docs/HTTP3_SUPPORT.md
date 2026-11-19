# HTTP/3 traffic listener support

The opt-in isolated HTTPS traffic listener accepts `httpVersion` values `1.1`, `2`, or `3` in `YARP_LISTENERS_CONFIG_FILE`.

- `1.1` and `2` keep their existing single-protocol TLS behavior.
- `3` enables HTTP/1.1 and HTTP/2 over TLS/TCP and HTTP/3 over TLS 1.3/QUIC/UDP on the configured `trafficHttpsPort`. This lets existing TCP clients continue to work while supporting HTTP/3 clients.
- Kestrel advertises HTTP/3 with `Alt-Svc` on HTTPS responses when this endpoint is enabled.
- The ordinary traffic HTTP listener remains HTTP/1.1. Management and metrics listeners remain HTTP/1.1 over mutually authenticated TLS and do not enable QUIC.

Before setting `httpVersion` to `3`, install a .NET 10 runtime with MsQuic support and allow both TCP and UDP to the HTTPS traffic port through host, network and cloud firewalls. Clients may continue using HTTP/1.1 or HTTP/2 when UDP is unavailable. Use a valid configured TLS certificate and verify certificate renewal/rotation separately. The Windows CI runner performs real loopback HTTP/1.1, HTTP/2 and HTTP/3 requests. The current Ubuntu-hosted runner lacks MsQuic and reports an explicit `SKIP` for QUIC wire acceptance; parser and fail-closed behavior are still exercised there. Physical network, proxy, firewall, capacity, browser and customer protocol acceptance are still required before production use.
